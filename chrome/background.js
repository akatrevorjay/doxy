// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview This file initializes the background page by loading a
 * ProxyErrorHandler, and resetting proxy settings if required.
 *
 * @author Mike West <mkwst@google.com>
 */

document.addEventListener("DOMContentLoaded", function () {
  var errorHandler = new ProxyErrorHandler();

  // If this extension has already set the proxy settings, then reset it
  // once as the background page initializes.  This is essential, as
  // incognito settings are wiped on restart.
  var persistedSettings = ProxyFormController.getPersistedSettings();

  if (persistedSettings !== null) {
      if (persistedSettings.regular.mode == 'pac_script') {
        // Refresh every 5 seconds
        setInterval(function() {
          // call URL with random string to avoid URL cache
          // TODO Don't hardcode this.
          persistedSettings.regular.pacScript.url = 'http://127.0.0.69/_doxy/pac.js?nocache'+Math.floor((Math.random() * 1000) + 1);
          chrome.proxy.settings.set({'value': persistedSettings.regular});
        }, 5000);
      }

      chrome.proxy.settings.set(
        {'value': persistedSettings.regular}
      );
  }
});

