#!/usr/bin/env node
import { main } from "../dist/cli.js";
main().then((code) => { if (code) process.exit(code); });
