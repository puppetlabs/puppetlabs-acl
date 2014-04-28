require 'puppetlabs_spec_helper/module_spec_helper'
#require 'puppet/test/test_helper'
require 'pathname'
require 'tmpdir'
require 'fileutils'
require 'puppet/util/windows/security'

def grant_everyone_full_access(path)
  sd = Puppet::Util::Windows::Security.get_security_descriptor(path)
  sd.dacl.allow(
    'S-1-1-0', #everyone
    Windows::File::FILE_ALL_ACCESS,
    Windows::File::OBJECT_INHERIT_ACE | Windows::File::CONTAINER_INHERIT_ACE)
  Puppet::Util::Windows::Security.set_security_descriptor(path, sd)
end

RSpec.configure do |config|
  tmpdir = Dir.mktmpdir("rspecrun_acl")
  oldtmpdir = Dir.tmpdir()
  ENV['TMPDIR'] = tmpdir

  if Puppet::Util::Platform.windows?
    config.output_stream = $stdout
    config.error_stream = $stderr
    config.formatters.each { |f| f.instance_variable_set(:@output, $stdout) }
  end

  #config.before :each do
  #  # Disabling garbage collection inside each test, and only running it at
  #  # the end of each block, gives us an ~ 15 percent speedup, and more on
  #  # some platforms *cough* windows *cough* that are a little slower.
  #  GC.disable
  #end
  #
  #config.after :each do
  #  # This will perform a GC between tests, but only if actually required.  We
  #  # experimented with forcing a GC run, and that was less efficient than
  #  # just letting it run all the time.
  #  GC.enable
  #end

  config.after :suite do
    # return to original tmpdir
    ENV['TMPDIR'] = oldtmpdir
    FileUtils.rm_rf(tmpdir)
  end
end

# We need this because the RAL uses 'should' as a method.  This
# allows us the same behaviour but with a different method name.
class Object
  alias :must :should
  alias :must_not :should_not
end
