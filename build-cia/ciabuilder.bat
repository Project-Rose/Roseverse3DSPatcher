@echo off
cd /d "%~dp0"

bannertool.exe makebanner -i ../meta/banner.png -a ../meta/banner.wav -o banner.bnr
bannertool.exe makesmdh -s "Roseverse Patcher" -l "Roseverse Patcher" -p "Virtualle and Zeroskill1" -i ../meta/icon.png  -o icon.icn
makerom.exe -f cia -o ../RoseversePatcher3DS.cia -DAPP_ENCRYPTED=false -rsf app.rsf -target t -exefslogo -elf ../RoseversePatcher3DS.elf -icon icon.icn -banner banner.bnr
echo Finished! CIA has been built!
