# Roséverse 3DS Patcher

This application patches Miiverse data to gain access to Roséverse on the Nintendo 3DS.

> [!IMPORTANT]
> You will need a Pretendo Network ID (PNID) linked and active to use this application. Authentication data for Roséverse cannot be used for Nintendo Network IDs (NNID). Make sure you have selected "Pretendo" in Nimbus.

# Usage

Home Menu:
- Download the [latest release CIA](https://github.com/Project-Rose/RoserversePatcher3DS/releases/latest/Roseverse3DSPatcher.cia) and place it on your SD Card
- Go into FBI or your preferred CIA installer and select the file, then click "Install and Delete".
- Return to the Home Menu and close your CIA installer, if the app does not appear, try going into a different app then going back out and closing that app.

Homebrew Launcher:
- Download the [latest release 3DSX](https://github.com/Project-Rose/RoserversePatcher3DS/releases/latest/Roseverse3DSPatcher.3dsx) and place it into the `3ds` folder on your SD card.
- Launch Roséverse 3DS Patcher in the Homebrew Launcher.

> [!WARNING]
> This application may cause crashes when handled in certain ways, if you run into a crash, contact a developer in the [Project Rose Discord Server.](https://discord.gg/KRHHQFKB6W)

# Building from source

## Prerequisites
First of all, you need [devKitPro with the 3DS toolkit installed](https://devkitpro.org/wiki/Getting_Started)

After you have completed this, open a terminal on your system and enter the following command:
<details>
<summary>Windows</summary>
  
  ```bash
pacman -S 3ds-curl
```
  
</details>

<details>
<summary>Linux/Mac</summary>
  
  ```bash
dkp-pacman -S 3ds-curl
```
  
</details>

After this, clone this repository and simply run:
```bash
make
```

If you want a .cia, first run make, then run:
```bash
make cia
```

# License

See [LICENSE](./LICENSE).
