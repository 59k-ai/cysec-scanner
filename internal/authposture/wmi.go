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
	// wmiNamespaceCIMV2 is the default WMI namespace the installed-software class
	// lives in.
	wmiNamespaceCIMV2 = "//./root/cimv2"
	// installedProgramsWQL reads the READ-ONLY installed-programs class. It is
	// deliberately NOT Win32_Product (banned, Semgrep G14 — querying that class
	// triggers an MSI reconfigure on the target, which would be a write).
	installedProgramsWQL = "SELECT Name,Version,Vendor FROM Win32_InstalledWin32Program"
	// installSourceWMI labels a software row's provenance as a WMI read.
	installSourceWMI = "wmi"
	// wmiCallTimeout bounds each RPC call so a dead host fails fast rather than
	// hanging the bounded pool.
	wmiCallTimeout = 30 * time.Second
	// wmiEnumBatch is the WCO smart-enumerator page size (objects per round-trip).
	wmiEnumBatch = 100

	noteKeyWMI         = "authposture_wmi"
	noteKeyWMISoftware = "authposture_wmi_software"
)

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

// liveWMIRead reads one real WMI class (installed software) from a Windows host
// over a SEALED DCOM/NTLM session and returns it as hostFacts. It lifts the
// spike-001 flow: dial :135, IObjectExporter -> IActivation.RemoteActivation
// (Level1Login class, TCP protocol sequence) -> dial the OXID ncacn_ip_tcp
// endpoint -> share one security context across Level1Login + RemoteUnknown2 ->
// NTLMLogin on root/cimv2 -> ExecQuery -> page the WCO smart enumerator.
//
// SEAL is the mandatory default on every bind (spike-settled): sign-only returns
// AccessDenied in the Win11 BitLocker namespace. The whole function NEVER raises
// — every branch of the go-msrpc error surface is mapped to a per-check evidence
// note and returned, so the stage stays never-raises (ENG-06 / D-06). The
// credential is used only to authenticate; it is never logged (the logger is a
// no-op sink) and never written into any payload field.
func liveWMIRead(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	hf := newHostFacts()
	host := targetHost(ai)
	if host == "" {
		hf.note(noteKeyWMI, "no_address")
		return hf
	}
	registerWMICredential(cred)

	// A no-op logger: go-msrpc debug output must never reach stderr (it could echo
	// authentication material), so it is discarded outright.
	log := zerolog.Nop()

	sctx := gssapi.NewSecurityContext(ctx)

	cc, err := dcerpc.Dial(sctx, net.JoinHostPort(host, "135"), dcerpc.WithLogger(log), dcerpc.WithTimeout(wmiCallTimeout))
	if err != nil {
		hf.note(noteKeyWMI, "dial_135: "+err.Error())
		return hf
	}
	defer cc.Close(sctx)

	oxe, err := iobjectexporter.NewObjectExporterClient(sctx, cc, dcerpc.WithSeal())
	if err != nil {
		hf.note(noteKeyWMI, "object_exporter: "+err.Error())
		return hf
	}
	srv, err := oxe.ServerAlive2(sctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		hf.note(noteKeyWMI, "server_alive2: "+err.Error())
		return hf
	}
	iact, err := iactivation.NewActivationClient(sctx, cc, dcerpc.WithSeal())
	if err != nil {
		hf.note(noteKeyWMI, "activation_client: "+err.Error())
		return hf
	}
	act, err := iact.RemoteActivation(sctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{7}, // 7 = ncacn_ip_tcp
	})
	if err != nil {
		hf.note(noteKeyWMI, "remote_activation: "+err.Error())
		return hf
	}
	if act.HResult != 0 {
		hf.note(noteKeyWMI, "remote_activation: "+hresult.FromCode(uint32(act.HResult)).Error())
		return hf
	}

	wcc, err := dcerpc.Dial(sctx, host, append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
		dcerpc.WithLogger(log), dcerpc.WithTimeout(wmiCallTimeout))...)
	if err != nil {
		hf.note(noteKeyWMI, "dial_oxid: "+err.Error())
		return hf
	}
	defer wcc.Close(sctx)

	// One security context shared by every interface on the OXID connection.
	octx := gssapi.NewSecurityContext(sctx)
	l1, err := iwbemlevel1login.NewLevel1LoginClient(octx, wcc, dcom.WithIPID(act.InterfaceData[0].IPID()), dcerpc.WithSeal())
	if err != nil {
		hf.note(noteKeyWMI, "level1login: "+err.Error())
		return hf
	}
	irem, err := iremunknown2.NewRemoteUnknown2Client(octx, wcc, dcom.WithIPID(act.RemoteUnknown))
	if err != nil {
		hf.note(noteKeyWMI, "remunknown2: "+err.Error())
		return hf
	}

	this := &dcom.ORPCThis{Version: srv.COMVersion}
	login, err := l1.NTLMLogin(octx, &iwbemlevel1login.NTLMLoginRequest{This: this, NetworkResource: wmiNamespaceCIMV2})
	if err != nil {
		hf.note(noteKeyWMI, "ntlm_login: "+err.Error())
		return hf
	}
	svc, err := iwbemservices.NewServicesClient(octx, wcc, dcom.WithIPID(login.Namespace.InterfacePointer().IPID()), dcerpc.WithSeal())
	if err != nil {
		hf.note(noteKeyWMI, "services_client: "+err.Error())
		return hf
	}

	rows, err := execWMIQuery(octx, wcc, irem, svc, this, installedProgramsWQL)
	if err != nil {
		hf.note(noteKeyWMISoftware, err.Error())
		return hf
	}
	for _, row := range rows {
		hf.software = append(hf.software, softwareItemFromRow(ai.ExternalID, row))
	}
	hf.note(noteKeyWMISoftware, fmt.Sprintf("read %d installed programs over sealed wmi", len(rows)))
	return hf
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

// softwareItemFromRow maps one Win32_InstalledWin32Program row to a strict
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
