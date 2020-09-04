
sanity_check_sources = 'sanity.cc'
sanity_check = executable('sanity-check', sanity_check_sources,
  dependencies: gtest)
test('sanity check', sanity_check)

basic_sources = 'basic.cc'
basic = executable('basic', basic_sources,
  dependencies: gtest, link_with: u2f_emu, link_depends: setup_dir)
test('sanity check', basic)

payload_sources = 'payload.cc'
payload = executable('payload', payload_sources,
  include_directories: inc,
  dependencies: gtest, link_with: u2f_emu_testing)
test('payload', payload)

subdir('usb')
