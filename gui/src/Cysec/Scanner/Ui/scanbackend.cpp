// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "scanbackend.h"

#include <QMetaType>

namespace {

// Queued connections (the process transport delivers events across the
// event loop) need ScanEvent registered before the first emission. The moc
// output is included below so this object file, and with it this static
// initialiser, is always linked whenever ScanBackend's meta-object is used,
// even from a STATIC library.
[[maybe_unused]] const int kScanEventMetaTypeId = qRegisterMetaType<ScanEvent>("ScanEvent");

} // namespace

#include "moc_scanbackend.cpp"
