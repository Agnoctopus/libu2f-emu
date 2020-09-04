usb_sources = 'usb.cc'
usb = executable('usb', usb_sources,
  include_directories: inc,
  dependencies: gtest, link_with: u2f_emu_testing)
test('usb', usb)

message_sources = 'message.cc'
message = executable('message', message_sources,
  include_directories: inc,
  dependencies: gtest, link_with: u2f_emu_testing)
test('message', message)

packet_sources = 'packet.cc'
packet= executable('us', packet_sources,
  include_directories: inc,
  dependencies: gtest, link_with: u2f_emu_testing)
test('packet', packet)
