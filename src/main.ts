// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 2351485 ALBERTA INC.

import { registerSW } from "virtual:pwa-register";
import { applyTheme, loadThemeChoice } from "./ui/appearance.js";
import { boot } from "./ui/app.js";
import "./styles.css";

// Paint the user's skin (or the device default) before anything
// renders, so the app never flashes the wrong colours.
applyTheme(loadThemeChoice());

// Offline app shell: the service worker precaches the whole client
// on first visit. There are no network calls afterwards — the app
// has no server. (connect-src 'none' in the CSP enforces it.)
registerSW({ immediate: true });

void boot();
