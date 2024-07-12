/*
 Copyright 2023 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

"use strict";
const $ = document.querySelector.bind(document);
const $$ = document.querySelectorAll.bind(document);
EventTarget.prototype.on = EventTarget.prototype.addEventListener;

function base64decode(str) {
  return new Uint8Array([...atob(str)].map((a) => a.charCodeAt(0)))
}

function sleep(ms) {
  return new Promise((done, fail) => {
    setTimeout(done, ms)
  })
}

async function progress(message) {
  $(message).style.visibility = "visible";
  await sleep(1000)
}

document.on("DOMContentLoaded", async (e) => {
  const ISSUER = location.origin;

  $("#yes").on("click", async (e) => {
    await progress("#issuing");

    // token issue request
    const option = {
      privateToken: {
        version: 1,
        operation: "token-request",
        issuer: ISSUER
      }
    };
    const res = await fetch("/private-state-token/issuance", option);
    const text = await res.text();
    console.log({ text });

    // check token exists
    const token = await document.hasPrivateToken(ISSUER);
    console.log({ token });

    sleep(1000);
    if (token) {
      await progress("#issued")
    } else {
      // TODO: failure case
    }

    await progress("#back");

  });

});
