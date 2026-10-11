// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

(async function(testRunner) {
  const {dp} = await testRunner.startBlank(
      'HTTPPS cookie namespaces survive DevTools set/get/delete operations.');
  await dp.Network.enable();
  const https = 'https://example.test:443/';
  const httpps = 'httpps://example.test:443/';
  for (const [url, value] of [[https, 'https'], [httpps, 'httpps']]) {
    const response = await dp.Network.setCookie({
      url, name: 'session', value, secure: true, sameSite: 'None'
    });
    testRunner.log(`Set ${value}: ${response.result?.success}`);
  }
  async function show(label, urls) {
    const {result} = await dp.Network.getCookies({urls});
    testRunner.log(label + ': ' + result.cookies
        .map(cookie => `${cookie.value}/${cookie.sourceScheme}`).sort().join(', '));
  }
  await show('HTTPS', [https]);
  await show('HTTPPS', [httpps]);
  await show('Both', [https, httpps]);
  const mismatch = await dp.Network.setCookie({
    url: httpps, name: 'session', value: 'wrong', sourceScheme: 'Secure'
  });
  testRunner.log(`Reject relabel: ${!!mismatch.error}`);
  await dp.Network.deleteCookies({url: httpps, name: 'session'});
  await show('After HTTPPS delete', [https, httpps]);
  await dp.Network.setCookie({
    domain: 'example.test', sourceScheme: 'Httpps', name: 'session',
    value: 'httpps', secure: true, sameSite: 'None'
  });
  await dp.Network.deleteCookies({url: https, name: 'session'});
  await show('After HTTPS delete', [https, httpps]);
  testRunner.completeTest();
});
