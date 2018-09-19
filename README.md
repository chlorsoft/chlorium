# Oxidan: Sensible browsing

## Feature Highlights
- [x] Up to date - releases as close as possible to Chrome
- [x] Built on top of stable Chromium
- [x] Tracking Protection Filter with rules based on Firefox's Tracking Protection list (uses lists maintained by [Disconnect](https://github.com/disconnectme/disconnect-tracking-protection))
- [x] "Do Not Track" setting enabled by default

## Project Principles
- Align default privacy-related features to Firefox while maintaining a balance with available Chrome features
- Release as close as possible to current stable Chromium version to maintain a stable and consistent user experience and achieve closer alignment of bugs with upstream
- Minimal code changes for features to lower chances of upstream conflicts and minimise ongoing maintenance

## Credits
- The [Chromium](https://www.chromium.org/) project and developers
- Special mention to [csagan5](https://github.com/csagan5) for his wonderful work on [Bromite](https://www.bromite.org/).
- Oxidan's tracking protection filter was based on Bromite's adblock engine. Code to generate blocking rules was adapted from Mozilla's [shavar-list-creation](https://github.com/mozilla-services/shavar-list-creation) script.
- The team responsible for [Brave](https://brave.com/), in particular for their work on the [Android version](https://github.com/brave/browser-android-tabs) and associated documentation in their [Wiki](https://github.com/brave/browser-android-tabs/wiki).

## Licence
The patches, scripts and source code published as part of the Oxidan project are released under GNU GPL v3.
