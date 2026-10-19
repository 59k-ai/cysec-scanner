// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	iactivation "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	iobjectexporter "github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	iremunknown2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/iremunknown2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	iwbemfetchsmartenum "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemfetchsmartenum/v0"
	iwbemlevel1login "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	iwbemservices "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
	iwbemwcosmartenum "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemwcosmartenum/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"

	// Blank imports register the Win32 + WMI error-code tables so a remote
	// HRESULT maps to a human-readable, branchable error string (bad creds ->
	// AccessDenied, missing feature -> StatusInvalidNamespace, ...).
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// wmiReaderFunc is the injectable WMI reader seam. Tests swap it for a fake that
// returns deterministic facts without touching a real host; production uses
// liveWMIRead. It returns facts only — authposture.go performs the single merge.
type wmiReaderFunc func(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts

// readWMI is the package-var seam the stage calls; swapped in tests.
var readWMI wmiReaderFunc = liveWMIRead

const (
	// The three WMI namespaces the full D-04 class set lives across. The
	// installed-software/OS/patch/service/event-log classes live in the default
	// root/cimv2; Defender and BitLocker each live in their own namespace and are
	// read over the SAME sealed session via a per-namespace NTLMLogin.
	wmiNamespaceCIMV2     = "//./root/cimv2"
	wmiNamespaceDefender  = "//./root/Microsoft/Windows/Defender"
	wmiNamespaceBitLocker = "//./root/cimv2/Security/MicrosoftVolumeEncryption"

	// installedProgramsWQL reads the READ-ONLY installed-programs class. It is
	// deliberately NOT the MSI-reconfiguring installed-product class (banned,
	// Semgrep G14 — querying that class triggers an MSI reconfigure on the target,
	// which would be a write).
	osWQL                = "SELECT Caption,Version,BuildNumber,OSArchitecture,CSName FROM Win32_OperatingSystem"
	quickFixWQL          = "SELECT HotFixID,Description FROM Win32_QuickFixEngineering"
	serviceWQL           = "SELECT Name,State,StartMode,StartName FROM Win32_Service"
	installedProgramsWQL = "SELECT Name,Version,Vendor FROM Win32_InstalledWin32Program"
	eventlogWQL          = "SELECT LogfileName,MaxFileSize,OverWritePolicy FROM Win32_NTEventlogFile"
	encryptableVolumeWQL = "SELECT DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume"
	defenderWQL          = "SELECT AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge FROM MSFT_MpComputerStatus"

	// installSourceWMI labels a software row's provenance as a WMI read.
	installSourceWMI = "wmi"
	// wmiCallTimeout bounds each RPC call so a dead host fails fast rather than
	// hanging the bounded pool.
	wmiCallTimeout = 30 * time.Second
	// wmiEnumBatch is the WCO smart-enumerator page size (objects per round-trip).
	wmiEnumBatch = 100

	// checkStatusCollected is the configuration_checks Status this stage stamps.
	// The scanner emits EVIDENCE, never a compliance verdict (CLAUDE.md
	// compliance-purity rule / CONTEXT): the NIS2 mapping that decides pass/warn/
	// fail against an expectation is applied deterministically CLOUD-SIDE. Here
	// "pass" means only "evidence collected"; the raw observation lives in
	// ObservedValue and ExpectedValue is left empty (no expectation is asserted).
	// It is one of the required {pass,warn,fail} enum members (payload.go).
	checkStatusCollected = "pass"
	// severityInfo is the posture-evidence severity (one of the required
	// {critical,high,medium,low,info} enum members). Evidence rows carry info;
	// severity weighting is a cloud-side concern.
	severityInfo = "info"

	noteKeyWMI         = "authposture_wmi"
	noteKeyWMISoftware = "authposture_wmi_software"
)

// wmiClassNoteKey derives the per-class evidence-note key for a degraded read of
// one WMI class (e.g. a missing Defender namespace -> StatusInvalidNamespace).
// Keying by class keeps one class's failure from masking another's.
func wmiClassNoteKey(class string) string { return noteKeyWMI + "_" + class }

// wmiQuery is one row of the authoritative D-04 class table: the namespace to log
// into, the class name (parity key + note key), the exact WQL to mirror the
// Python agent's read, and the mapper that folds decoded rows into hostFacts.
type wmiQuery struct {
	namespace string
	class     string
	wql       string
	mapRows   func(externalID string, rows []wmio.Values, hf *hostFacts)
}

// wmiQueries is the full spike-validated D-04 class set across the three
// namespaces, mirrored EXACTLY from the Python agent's read list so the Phase-8
// cutover is a true parity swap (WINAD-05). The MSI-reconfiguring installed-
// product class is deliberately absent (Semgrep G14); the read-only
// installed-programs class is its substitute. A parity test locks this set.
var wmiQueries = []wmiQuery{
	{wmiNamespaceCIMV2, "Win32_OperatingSystem", osWQL, mapOperatingSystem},
	{wmiNamespaceCIMV2, "Win32_QuickFixEngineering", quickFixWQL, mapQuickFix},
	{wmiNamespaceCIMV2, "Win32_Service", serviceWQL, mapServices},
	{wmiNamespaceCIMV2, "Win32_InstalledWin32Program", installedProgramsWQL, mapInstalledPrograms},
	{wmiNamespaceCIMV2, "Win32_NTEventlogFile", eventlogWQL, mapEventLogs},
	{wmiNamespaceBitLocker, "Win32_EncryptableVolume", encryptableVolumeWQL, mapEncryptableVolumes},
	{wmiNamespaceDefender, "MSFT_MpComputerStatus", defenderWQL, mapDefender},
}

// wmiCredOnce registers the single read-only domain scan account (D-05) with the
// go-msrpc GSSAPI credential store exactly once per process. Every Windows host
// uses the SAME account, so a one-time registration is correct and keeps the
// concurrent host pool free of repeated global mutation.
var wmiCredOnce sync.Once

func registerWMICredential(cred scanCredential) {
	wmiCredOnce.Do(func() {
		gssapi.AddCredential(credential.NewFromPassword(cred.domainUser, cred.password))
		gssapi.AddMechanism(ssp.NTLM)
	})
}

// wmiSession runs WQL queries against one host, caching exactly one IWbemServices
// client per namespace over a single shared sealed DCOM connection. liveWMISession
// is the real implementation; tests inject a fake returning canned rows/errors
// per namespace so the class table + row mapping are exercised on Linux CI
// without a live Windows target.
type wmiSession interface {
	query(ctx context.Context, namespace, wql string) ([]wmio.Values, error)
	close()
}

// openWMISession dials the host and establishes the sealed DCOM session. It is a
// package-var seam swapped in tests (a fake session, or a dial error) so the
// never-raises mapping path is testable off-Windows.
var openWMISession = openLiveWMISession

// liveWMIRead reads the full D-04 WMI class set from a Windows host over ONE
// sealed DCOM/NTLM session and returns the mapped facts as hostFacts. The session
// is dialed once (openWMISession); collectWMIClasses then iterates the class table,
// logging into each distinct namespace once and mapping each class onto its v6
// payload target.
//
// SEAL is the mandatory default on every bind (spike-settled): sign-only returns
// AccessDenied in the Win11 BitLocker namespace. The whole function NEVER raises —
// a dial/session failure or any per-class failure is mapped to a per-check
// evidence note and returned, so the stage stays never-raises (ENG-06 / D-06).
// The credential is used only to authenticate; it is never logged (the logger is a
// no-op sink) and never written into any payload field.
func liveWMIRead(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	hf := newHostFacts()
	host := targetHost(ai)
	if host == "" {
		hf.note(noteKeyWMI, "no_address")
		return hf
	}
	registerWMICredential(cred)

	sess, err := openWMISession(ctx, host)
	if err != nil {
		hf.note(noteKeyWMI, "session: "+err.Error())
		return hf
	}
	defer sess.close()

	collectWMIClasses(ctx, sess, ai.ExternalID, &hf)
	return hf
}

// collectWMIClasses iterates the D-04 class table over an established session,
// mapping each class onto hostFacts. A per-class failure (missing namespace,
// AccessDenied, unreachable) is recorded as a per-check evidence note and the
// loop continues with the remaining classes — one class's failure NEVER aborts
// the others and NEVER returns a stage error (never-raises).
func collectWMIClasses(ctx context.Context, sess wmiSession, externalID string, hf *hostFacts) {
	for _, q := range wmiQueries {
		if ctx.Err() != nil {
			hf.note(noteKeyWMI, "cancelled")
			return
		}
		rows, err := sess.query(ctx, q.namespace, q.wql)
		if err != nil {
			hf.note(wmiClassNoteKey(q.class), err.Error())
			continue
		}
		q.mapRows(externalID, rows, hf)
	}
}

// --- per-class row mappers (deterministic evidence; never a verdict) ---

// mapOperatingSystem folds Win32_OperatingSystem onto the asset-level OS fields.
func mapOperatingSystem(_ string, rows []wmio.Values, hf *hostFacts) {
	if len(rows) == 0 {
		return
	}
	r := rows[0]
	if caption := wmioString(r["Caption"]); caption != "" {
		hf.operatingSystem = caption
	}
	if ver := wmioString(r["Version"]); ver != "" {
		hf.osVersion = ver
	}
}

// mapQuickFix folds Win32_QuickFixEngineering (installed hotfixes) onto missing_kbs
// rows (HotFixID -> KBID, Description -> Title). CVE and released_date are left
// unset; the severity weighting / missing-vs-installed reconciliation is a
// cloud-side concern, so the row carries info severity as neutral evidence.
func mapQuickFix(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		kb := wmioString(r["HotFixID"])
		if kb == "" {
			continue
		}
		hf.missingKbs = append(hf.missingKbs, payload.MissingKbItem{
			AssetExternalID: externalID,
			KBID:            kb,
			Title:           wmioString(r["Description"]),
			Severity:        severityInfo,
		})
	}
}

// mapInstalledPrograms folds the read-only installed-programs class onto
// software_inventory rows.
func mapInstalledPrograms(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		hf.software = append(hf.software, softwareItemFromRow(externalID, r))
	}
	hf.note(noteKeyWMISoftware, fmt.Sprintf("read %d installed programs over sealed wmi", len(rows)))
}

// mapServices folds Win32_Service rows onto configuration_checks evidence (one
// row per service: observed State / StartMode / StartName).
func mapServices(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		name := wmioString(r["Name"])
		if name == "" {
			continue
		}
		observed := fmt.Sprintf("State=%s;StartMode=%s;StartName=%s",
			wmioString(r["State"]), wmioString(r["StartMode"]), wmioString(r["StartName"]))
		hf.configChecks = append(hf.configChecks,
			configCheck(externalID, "win_service:"+name, "Windows service "+name, observed))
	}
}

// mapEventLogs folds Win32_NTEventlogFile rows onto configuration_checks evidence
// (observed MaxFileSize / OverWritePolicy per log file).
func mapEventLogs(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		logName := wmioString(r["LogfileName"])
		if logName == "" {
			continue
		}
		observed := fmt.Sprintf("MaxFileSize=%s;OverWritePolicy=%s",
			wmioString(r["MaxFileSize"]), wmioString(r["OverWritePolicy"]))
		hf.configChecks = append(hf.configChecks,
			configCheck(externalID, "win_eventlog:"+logName, "Windows event log "+logName, observed))
	}
}

// mapEncryptableVolumes folds Win32_EncryptableVolume (BitLocker) rows onto
// configuration_checks evidence (observed DriveLetter / ProtectionStatus per
// volume). This class lives in the BitLocker namespace, which returns AccessDenied
// under sign-only — seal is mandatory on its bind (spike-settled).
func mapEncryptableVolumes(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		drive := wmioString(r["DriveLetter"])
		code := "bitlocker:volume"
		if drive != "" {
			code = "bitlocker:" + drive
		}
		observed := fmt.Sprintf("DriveLetter=%s;ProtectionStatus=%s",
			drive, wmioString(r["ProtectionStatus"]))
		hf.configChecks = append(hf.configChecks,
			configCheck(externalID, code, "BitLocker volume protection status", observed))
	}
}

// mapDefender folds MSFT_MpComputerStatus (Defender) rows onto configuration_checks
// evidence (observed AntivirusEnabled / RealTimeProtectionEnabled / signature age).
func mapDefender(externalID string, rows []wmio.Values, hf *hostFacts) {
	for _, r := range rows {
		observed := fmt.Sprintf("AntivirusEnabled=%s;RealTimeProtectionEnabled=%s;AntivirusSignatureAge=%s",
			wmioString(r["AntivirusEnabled"]), wmioString(r["RealTimeProtectionEnabled"]),
			wmioString(r["AntivirusSignatureAge"]))
		hf.configChecks = append(hf.configChecks,
			configCheck(externalID, "defender:status", "Microsoft Defender status", observed))
	}
}

// configCheck builds one configuration_checks evidence row with the neutral
// collected status (see checkStatusCollected) and info severity. ExpectedValue is
// left empty: the scanner asserts no expectation — the compliance mapping is
// applied cloud-side.
func configCheck(externalID, checkCode, title, observed string) payload.ConfigurationCheckItem {
	return payload.ConfigurationCheckItem{
		AssetExternalID: externalID,
		CheckCode:       checkCode,
		Title:           title,
		Status:          checkStatusCollected,
		Severity:        severityInfo,
		ObservedValue:   observed,
	}
}

// openLiveWMISession performs the spike-001 DCOM bring-up and returns a session
// that reuses one shared sealed OXID connection for every per-namespace login and
// query: dial :135, IObjectExporter -> IActivation.RemoteActivation (Level1Login
// class, TCP protocol sequence) -> dial the OXID ncacn_ip_tcp endpoint -> share one
// security context across Level1Login + RemoteUnknown2. Every bind carries
// dcerpc.WithSeal().
func openLiveWMISession(ctx context.Context, host string) (wmiSession, error) {
	// A no-op logger: go-msrpc debug output must never reach stderr (it could echo
	// authentication material), so it is discarded outright.
	log := zerolog.Nop()

	sctx := gssapi.NewSecurityContext(ctx)

	cc, err := dcerpc.Dial(sctx, net.JoinHostPort(host, "135"), dcerpc.WithLogger(log), dcerpc.WithTimeout(wmiCallTimeout))
	if err != nil {
		return nil, fmt.Errorf("dial_135: %w", err)
	}
	oxe, err := iobjectexporter.NewObjectExporterClient(sctx, cc, dcerpc.WithSeal())
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("object_exporter: %w", err)
	}
	srv, err := oxe.ServerAlive2(sctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("server_alive2: %w", err)
	}
	iact, err := iactivation.NewActivationClient(sctx, cc, dcerpc.WithSeal())
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("activation_client: %w", err)
	}
	act, err := iact.RemoteActivation(sctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{7}, // 7 = ncacn_ip_tcp
	})
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("remote_activation: %w", err)
	}
	if act.HResult != 0 {
		cc.Close(sctx)
		return nil, fmt.Errorf("remote_activation: %s", hresult.FromCode(uint32(act.HResult)).Error())
	}

	wcc, err := dcerpc.Dial(sctx, host, append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
		dcerpc.WithLogger(log), dcerpc.WithTimeout(wmiCallTimeout))...)
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("dial_oxid: %w", err)
	}

	// One security context shared by every interface on the OXID connection.
	octx := gssapi.NewSecurityContext(sctx)
	l1, err := iwbemlevel1login.NewLevel1LoginClient(octx, wcc, dcom.WithIPID(act.InterfaceData[0].IPID()), dcerpc.WithSeal())
	if err != nil {
		wcc.Close(sctx)
		cc.Close(sctx)
		return nil, fmt.Errorf("level1login: %w", err)
	}
	irem, err := iremunknown2.NewRemoteUnknown2Client(octx, wcc, dcom.WithIPID(act.RemoteUnknown))
	if err != nil {
		wcc.Close(sctx)
		cc.Close(sctx)
		return nil, fmt.Errorf("remunknown2: %w", err)
	}

	return &liveWMISession{
		closeCtx: sctx,
		queryCtx: octx,
		cc:       cc,
		wcc:      wcc,
		l1:       l1,
		irem:     irem,
		this:     &dcom.ORPCThis{Version: srv.COMVersion},
		services: map[string]iwbemservices.ServicesClient{},
	}, nil
}

// liveWMISession is the real sealed DCOM session. It logs into each distinct
// namespace exactly once (caching the IWbemServices client) and runs each WQL
// query over the shared OXID connection.
type liveWMISession struct {
	closeCtx context.Context
	queryCtx context.Context
	cc       dcerpc.Conn
	wcc      dcerpc.Conn
	l1       iwbemlevel1login.Level1LoginClient
	irem     iremunknown2.RemoteUnknown2Client
	this     *dcom.ORPCThis
	services map[string]iwbemservices.ServicesClient
}

// query logs into the namespace (once, cached) and runs one WQL query. Every bind
// carries dcerpc.WithSeal(), INCLUDING the BitLocker namespace services client
// (sign-only returns AccessDenied there — spike-settled).
func (s *liveWMISession) query(_ context.Context, namespace, wql string) ([]wmio.Values, error) {
	svc, ok := s.services[namespace]
	if !ok {
		login, err := s.l1.NTLMLogin(s.queryCtx, &iwbemlevel1login.NTLMLoginRequest{This: s.this, NetworkResource: namespace})
		if err != nil {
			return nil, fmt.Errorf("ntlm_login: %w", err)
		}
		svc, err = iwbemservices.NewServicesClient(s.queryCtx, s.wcc,
			dcom.WithIPID(login.Namespace.InterfacePointer().IPID()), dcerpc.WithSeal())
		if err != nil {
			return nil, fmt.Errorf("services_client: %w", err)
		}
		s.services[namespace] = svc
	}
	return execWMIQuery(s.queryCtx, s.wcc, s.irem, svc, s.this, wql)
}

// close tears down the two shared connections (OXID then the :135 bootstrap).
func (s *liveWMISession) close() {
	if s.wcc != nil {
		s.wcc.Close(s.closeCtx)
	}
	if s.cc != nil {
		s.cc.Close(s.closeCtx)
	}
}

// execWMIQuery runs one WQL query and pages the WCO smart enumerator (one
// round-trip per wmiEnumBatch objects), returning each decoded row's property
// map. It is a verbatim lift of the spike's read path with read-only forward-only
// flags. Every error is wrapped, never a panic.
func execWMIQuery(ctx context.Context, wcc dcerpc.Conn, irem iremunknown2.RemoteUnknown2Client,
	svc iwbemservices.ServicesClient, this *dcom.ORPCThis, wql string) ([]wmio.Values, error) {

	enum, err := svc.ExecQuery(ctx, &iwbemservices.ExecQueryRequest{
		This:          this,
		QueryLanguage: &oaut.String{Data: "WQL"},
		Query:         &oaut.String{Data: wql},
		Flags:         int32(wmi.GenericFlagTypeForwardOnly | wmi.GenericFlagTypeReturnImmediately),
	})
	if err != nil {
		return nil, fmt.Errorf("exec_query: %w", err)
	}
	qif, err := irem.RemoteQueryInterface2(ctx, &iremunknown2.RemoteQueryInterface2Request{
		This: this,
		IPID: enum.Enum.InterfacePointer().IPID().GUID(),
		IIDs: []*dcom.IID{iwbemfetchsmartenum.FetchSmartEnumIID},
	})
	if err != nil {
		return nil, fmt.Errorf("qi_smartenum: %w", err)
	}
	fse, err := iwbemfetchsmartenum.NewFetchSmartEnumClient(ctx, wcc, dcom.WithIPID(qif.Interface[0].IPID()))
	if err != nil {
		return nil, fmt.Errorf("fetch_smartenum_client: %w", err)
	}
	se, err := fse.GetSmartEnum(ctx, &iwbemfetchsmartenum.GetSmartEnumRequest{This: this})
	if err != nil {
		return nil, fmt.Errorf("get_smartenum: %w", err)
	}
	wco, err := iwbemwcosmartenum.NewWCOSmartEnumClient(ctx, wcc, dcom.WithIPID(se.SmartEnum.InterfacePointer().IPID()))
	if err != nil {
		return nil, fmt.Errorf("wco_smartenum_client: %w", err)
	}
	classes := map[string]*wmio.Class{}
	rows := []wmio.Values{}
	for {
		ret, err := wco.Next(ctx, &iwbemwcosmartenum.NextRequest{This: this, Timeout: -1, Count: wmiEnumBatch})
		if err != nil {
			return rows, fmt.Errorf("next: %w", err)
		}
		if len(ret.Buffer) == 0 {
			return rows, nil
		}
		oa, err := wmi.UnmarshalObjectArrayWithClasses(ret.Buffer, classes)
		if err != nil {
			return rows, fmt.Errorf("unmarshal: %w", err)
		}
		for _, po := range oa.Objects {
			rows = append(rows, po.Object.Values())
		}
	}
}

// softwareItemFromRow maps one installed-programs row to a strict
// SoftwareInventoryItem. Optional string columns marshal to JSON null when empty
// (pointer discipline); the source class is recorded as evidence.
func softwareItemFromRow(externalID string, row wmio.Values) payload.SoftwareInventoryItem {
	return payload.SoftwareInventoryItem{
		AssetExternalID: externalID,
		DisplayName:     wmioString(row["Name"]),
		DisplayVersion:  wmioOptional(row["Version"]),
		Publisher:       wmioOptional(row["Vendor"]),
		InstallSource:   installSourceWMI,
		SourceEvidence:  map[string]string{"wmi_class": "Win32_InstalledWin32Program"},
	}
}

// targetHost resolves the address to dial for a host, preferring the IP, then
// the FQDN, then the hostname.
func targetHost(ai payload.AssetItem) string {
	if ai.IPAddress != nil && *ai.IPAddress != "" {
		return *ai.IPAddress
	}
	if ai.FQDN != "" {
		return ai.FQDN
	}
	return ai.Hostname
}

// wmioString coerces a decoded WMI property value to a string, "" when absent.
func wmioString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// wmioOptional returns a pointer to the string form of a WMI property value, or
// nil when the value is absent/empty (so the field marshals to JSON null).
func wmioOptional(v any) *string {
	s := wmioString(v)
	if s == "" {
		return nil
	}
	return &s
}
