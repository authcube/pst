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

"use strict"
const $ = document.querySelector.bind(document)
const $$ = document.querySelectorAll.bind(document)
EventTarget.prototype.on = EventTarget.prototype.addEventListener

function base64decode(str) {
    return new Uint8Array([...atob(str)].map((a) => a.charCodeAt(0)))
}

function sleep(ms) {
    return new Promise((done, fail) => {
        setTimeout(done, ms)
    })
}

async function progress(message) {
    $(message).style.display = "revert"
    await sleep(1000)
}

document.on("DOMContentLoaded", async (e) => {
    console.log(e)

    // const ISSUER = "https://private-state-token-issuer.glitch.me/"
    const ISSUER = "https://newpst.authfy.tech"

    async function verify_human(e) {
        e.preventDefault()
        $("dialog").showModal()

        await progress("#checking")

        // check token exists
        const token = await document.hasPrivateToken(ISSUER)
        console.log({ token })

        await progress("#hasTrustToken")

        if (token === false) {
            // no token
            await progress("#go2issuer")
        } else {
            await progress("#found")

            try {
                await progress("#redemption")

                // redemption request
                const res = await fetch(`${ISSUER}/private-state-token/redemption`, {
                    privateToken: {
                        version: 1,
                        operation: "token-redemption",
                        issuer: ISSUER,
                        refreshPolicy: "none"
                    }
                })
                console.log({ res })
            } catch (err) {
                await progress("#cached")
                console.info(err)
            }

            await progress("#verify")

            // send RR and echo Sec-Redemption-Record
            const res = await fetch(`/private-state-token/send-rr`, {
                privateToken: {
                    version: 1,
                    operation: "send-redemption-record",
                    issuers: [ISSUER]
                }
            })

            const body = await res.json()
            console.log(JSON.stringify(body, " ", " "))

            await progress("#finish")
            await sleep(1000)
            $("dialog").close()
            $("summary").removeEventListener("click", verify_human)
            e.target.click()
        }
    }

    try {
        $("summary").on("click", verify_human)
    } catch (error) {
        console.error(error)
        await progress("#failed")
    }
})