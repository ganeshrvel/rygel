#!/usr/bin/env node

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

'use strict';

const util = require('util');

let filename = __dirname + '/../build/koffi.node';
module.exports = require(filename);

module.exports.handle = util.deprecate(module.exports.opaque, 'The koffi.handle() function was deprecated in Koffi 2.1, use koffi.opaque() instead', 'KOFFI001');