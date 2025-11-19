rule fake_chrome_updater_dex_android {
  meta:
    description = "Fake Chrome updater classes*.dex (Android)"
    author = "Andras Gemes"
    date = "2025-11-18"
    sha256 = "59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029"
    ref1 = "https://shadowshell.io/fake-chrome-updater"
    ref2 = "https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/"

  strings:
    // This app can't run on your device.
    $0 = "ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw=="
    // OK
    $1 = "Gh8="
    // logcat -c
    $2 = "OTshTlkhdGtO"
    // logcat
    $3 = "OTshTlkh"
    // Logger got killed. Restarting.
    $4 = "GTshSl0ndCFCTHU/L0FUMDBoDWowJzJMSiE9KEoW"
    // Logger stopped.
    $5 = "GTshSl0ndDVZVyUkI0kW"

  condition:
    3 of them
}
