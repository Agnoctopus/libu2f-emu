project('u2f-emulated', ['c', 'cpp'], meson_version: '>= 0.52.0',
        version: '0.0.0',
        license: 'GPL2',
        default_options:
        ['warning_level=3',
        'werror=true',
        'c_std=c99',
        'cpp_std=c++11',
        'b_colorout=auto'])

compiler_c = meson.get_compiler('c')
compiler_ccx = meson.get_compiler('cpp')

openssl = dependency('openssl', version: '>= 1.1.0', required: true)
gtest = dependency('gtest',  version: '>= 1.10.0', required: false, main: true)

inc = include_directories('src')

if get_option('coverage')
  add_global_arguments('-g3', '--coverage', '-fno-inline',
    '-fno-inline-small-functions', '-fno-default-inline',
    '-fprofile-arcs', '-ftest-coverage', '-fkeep-inline-functions', '-fPIC',
    '-fkeep-static-functions', language: 'c')
  add_global_arguments('-g3', '--coverage', '-fno-inline',
    '-fno-inline-small-functions', '-fno-default-inline',
    '-fprofile-arcs', '-ftest-coverage', '-fkeep-inline-functions', '-fPIC',
    '-fkeep-static-functions', '-fno-elide-constructors', language: 'cpp')
  add_global_link_arguments('-lgcov', language: 'c')
  add_global_link_arguments('-lgcov', language: 'cpp')

  custom_target('cov', output: 'coverage',
    command: ['mkdir', '-p', '@OUTPUT@', '&&', 'cd', '@0@'.format(meson.source_root()), '&&',
      'gcovr', '-r', 'src/', '--html', '--html-details', '--html-title', 'Libu2f-emu coverage',
      '--object-directory', '@0@'.format(meson.build_root()),
      '-o', '@0@/coverage/index.html'.format(meson.build_root()), '-j2'])
endif

subdir('src')

if not gtest.found()
  warning('Skip test: gtest not found.')
else
  setup_dir = custom_target('setup_dir',
    output: '.u2f.tmp',
    command: ['@0@/scripts/setup.sh'.format(meson.source_root()), '@OUTPUT@'])
  subdir('tests')
endif

subdir('examples')

doxygen = find_program('doxygen', required : false)
if not doxygen.found()
  error('Skip doc: doxygen not found.')
else
  doc_config = configuration_data()
  doc_config.set('VERSION', meson.project_version())

  dot = find_program('dot', required : false)

  if dot.found()
    doc_config.set('HAVE_DOT', 'YES')
  else
    doc_config.set('HAVE_DOT', 'NO')
    error('Skip dot in doc: dot not found.')
  endif

  doc_config.set('top_srcdir', meson.source_root())
  doc_config.set('TOP_BUILDDIR', meson.build_root())

  doxyfile = configure_file(input: 'Doxyfile.in',
                            output: 'Doxyfile',
                            configuration: doc_config,
                            install: false)

  doc_dir = join_paths(get_option('datadir'), 'doc')

  html_target = custom_target('doc',
                              input: doxyfile,
                              output: 'doc',
                              command: [doxygen, doxyfile],
                              install_dir: get_option('datadir'))
endif
