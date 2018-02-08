require 'spec_helper_acceptance'

describe 'Parameter Target - Negative' do
  def acl_manifest(target)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      ->
      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      ->
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  windows_agents.each do |agent|
    context "Specify Blank Target on #{agent}" do
      target = ''
      it 'Execute Manifest' do
        on(agent, puppet('apply', '--debug'), stdin: acl_manifest(target), acceptable_exit_codes: [1]) do |result|
          assert_match(%r{Error:.*(A non-empty name must be specified|Empty string title at)}, result.stderr, 'Expected error was not detected!')
        end
      end
    end
  end

  windows_agents.each do |agent|
    context "Specify Target with Invalid Path Characters on #{agent}" do
      target = 'c:/temp/invalid_<:>|?*'
      it 'Execute Manifest' do
        on(agent, puppet('apply', '--debug'), stdin: acl_manifest(target)) do |result|
          assert_match(%r{Error:.*The filename, directory name, or volume label syntax is incorrect},
                       result.stderr, 'Expected error was not detected!')
        end
      end
    end
  end
end
