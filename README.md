Reversing a camera

* Bought [here](https://www.aliexpress.com/item/1005006287788979.html).
* App is [YsxLite](https://play.google.com/store/apps/details?id=com.ysxlite.cam&hl=en&gl=US)


Per [pictures](https://github.com/DavidVentura/cam-reverse/blob/master/pics/pcb.jpg?raw=true) the main chip is TXW817 ([chinese](https://www.taixin-semi.com/Product/ProductDetail?productId=306), [eng, google translate](https://www-taixin--semi-com.translate.goog/Product/ProductDetail?productId=306&_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en&_x_tr_pto=wapp))

The interesting implementation is in `libvdp.so`, part of the apk bundle. This repo uses Frida for live analysis of the .so file.


### Take APK from emulator/sacrificial device
```
adb shell pm list packages | grep ysx
adb shell pm path com.ysxlite.cam
adb shell pm path com.ysxlite.cam | while read -r line ; do adb pull $(echo $line | cut -d: -f2-) ;  done
```
### Push to sacrificial device
```
adb install-multiple *apk
```

### Frida install Android

[docs](https://frida.re/docs/android/)

