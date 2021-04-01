// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
const cxx = require("./cxx")().then((mod) => {
  var demangleCxx = mod.cwrap("cxx", "string", ["string"]);
  console.log(demangleCxx("_Z29api_internal_launch_ipykernelP7_objectS0_S0_"));
});
