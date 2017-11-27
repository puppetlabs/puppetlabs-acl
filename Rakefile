require 'rake'
require 'rspec/core/rake_task'
require 'puppetlabs_spec_helper/rake_tasks'
require 'puppet_blacksmith/rake_tasks' if Bundler.rubygems.find_name('puppet-blacksmith').any?
begin
  require 'beaker/tasks/test' unless RUBY_PLATFORM =~ /win32/
rescue LoadError
  #Do nothing, only installed with system_tests group 
end

task :default => [:test]

# The acceptance tests for ACL are written in standard beaker format however
# the preferred method is using beaker-rspec.  This rake task overrides the 
# default `beaker` task, which would normally use beaker-rspec, and instead
# invokes beaker directly.  This is only need while the module tests are migrated
# to the newer rspec-beaker format
task_exists = Rake.application.tasks.any? { |t| t.name == 'beaker' }
Rake::Task['beaker'].clear if task_exists
desc 'Run acceptance testing shim'
task :beaker do |t, args|
  beaker_cmd = "beaker --options-file spec/acceptance/.beaker-pe.cfg --hosts #{ENV['BEAKER_setfile']} --tests spec/acceptance/tests --keyfile #{ENV['BEAKER_keyfile']}"
  Kernel.system( beaker_cmd )
end

desc 'Run RSpec'
RSpec::Core::RakeTask.new(:test) do |t|
  t.pattern = 'spec/{unit}/**/*.rb'
#  t.rspec_opts = ['--color']
end

desc 'Generate code coverage'
RSpec::Core::RakeTask.new(:coverage) do |t|
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec']
end

desc 'Run Beaker PE Tests'
task :beaker_pe, [:hosts, :tests] do |t, args|
  args.with_defaults({:type => 'pe'})
  system(build_command(args))
end

desc 'Run Beaker Git Tests'
task :beaker_git, [:hosts, :tests] do |t, args|
  args.with_defaults({:type => 'git'})
  system(build_command(args))
end

def build_command(args)
  cmd_parts = []
  cmd_parts << "beaker"
  cmd_parts << "--options-file ./spec/acceptance/.beaker-#{args[:type]}.cfg"
  cmd_parts << "--hosts #{args[:hosts]}" if !args.hosts.empty?
  cmd_parts << "--tests #{args.tests}" if !args.tests.empty?
  cmd_parts.flatten.join(" ")
end
