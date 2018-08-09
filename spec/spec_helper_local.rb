require 'pathname'
require 'tmpdir'
require 'fileutils'

if Puppet.features.microsoft_windows?
  require 'puppet/util/windows/security'

  def take_ownership(path)
    path = path.tr('/', '\\')
    output = `takeown.exe /F #{path} /R /A /D Y 2>&1`
    puts "#{path} got error #{output}" if $CHILD_STATUS != 0 # check if the child process exited cleanly.
  end
end

RSpec.configure do |config|
  tmpdir = Dir.mktmpdir('rspecrun_acl')
  oldtmpdir = Dir.tmpdir
  ENV['TMPDIR'] = tmpdir

  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end

  config.after :suite do
    # return to original tmpdir
    ENV['TMPDIR'] = oldtmpdir
    if Puppet::Util::Platform.windows?
      take_ownership(tmpdir)
    end
    FileUtils.rm_rf(tmpdir)
  end
end

# We need this because the RAL uses 'should' as a method.  This
# allows us the same behaviour but with a different method name.
class Object
  alias must should
  alias must_not should_not
end
