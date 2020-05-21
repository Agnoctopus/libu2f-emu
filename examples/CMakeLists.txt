# Add subdirectories
add_subdirectory(usb)
add_subdirectory(nfc)
add_subdirectory(bluetooth)

# Examples target
add_custom_target(examples
    DEPENDS u2f-emu-usb
            u2f-emu-nfc
            u2f-emu-bluetooth)