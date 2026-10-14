#!/usr/bin/env node
'use strict';
// AgathOS - the MCP server of the plugin (stdio). All of it is in lib/mcp.js.
const fs = require('fs');
const path = require('path');

let version = '0.0.0';
try { version = JSON.parse(fs.readFileSync(path.join(__dirname, '.claude-plugin', 'plugin.json'), 'utf8')).version || version; } catch (_) { /* the version is only a label */ }
require('./lib/mcp').serve({ version });
