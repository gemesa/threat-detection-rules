rule xloader_loader_android {
  meta:
    description = "XLoader loader (Android)"
    author = "Andras Gemes"
    date = "2025-12-14"
    sha256 = "02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921"
    ref1 = "https://shadowshell.io/xloader"
    ref2 = "https://bazaar.abuse.ch/sample/02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921/"

  strings:
    // AndroidManifest.xml
    // Package name.
    // package="qqfzq.oeoop.lr.xnzcwr"
    $package = "qqfzq.oeoop.lr.xnzcwr" ascii wide

    // Junk permissions.
    // <uses-permission android:name="sedv.yfem.nfjzi"/>
    $permission0 = "sedv.yfem.nfjzi" ascii wide
    // <uses-permission android:name="pfoph.ryxrplq.dyek"/>
    $permission1 = "pfoph.ryxrplq.dyek" ascii wide
    // <uses-permission android:name="rzcad.qkwoooz.ualxq"/>
    $permission2 = "rzcad.qkwoooz.ualxq" ascii wide
    // <uses-permission android:name="bcemr.fjshnci.xfanv"/>
    $permission3 = "bcemr.fjshnci.xfanv" ascii wide
    // <uses-permission android:name="qrzsznko.gsgeyz.fztiy"/>
    $permission4 = "qrzsznko.gsgeyz.fztiy" ascii wide
    // <uses-permission android:name="pphnxshu.bhxe.rxgklxny"/>
    $permission5 = "pphnxshu.bhxe.rxgklxny" ascii wide

    // Package/class names.
    // android:name="gf6h8y8.GNuApplication"
    $pc0 = "gf6h8y8.GNuApplication" ascii wide
    // android:name="gf6h8y8.CrActivity"
    $pc1 = "gf6h8y8.CrActivity" ascii wide
    // android:name="gf6h8y8.Ux"
    $pc2 = "gf6h8y8.Ux" ascii wide
    // android:name="gf6h8y8.Ry"
    $pc3 = "gf6h8y8.Ry" ascii wide
    // android:name="gf6h8y8.Jz"
    $pc4 = "gf6h8y8.Jz" ascii wide
    // android:name="gf6h8y8.Li"
    $pc5 = "gf6h8y8.Li" ascii wide
    // android:name="gf6h8y8.Ap"
    $pc6 = "gf6h8y8.Ap" ascii wide
    // android:name="gf6h8y8.Yi"
    $pc7 = "gf6h8y8.Yi" ascii wide

  condition:
    10 of them
}
