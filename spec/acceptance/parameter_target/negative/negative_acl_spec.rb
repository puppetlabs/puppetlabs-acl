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
        execute_manifest_on(agent, acl_manifest(target), debug: true, exepect_failures: true) do |result|
          expect(result.stderr).to match(%r{Error:.*(A non-empty name must be specified|Empty string title at)})
        end
      end
    end
  end

  windows_agents.each do |agent|
    context "Specify Target with Invalid Path Characters on #{agent}" do
      target = 'c:/temp/invalid_<:>|?*'
      it 'Execute Manifest' do
        execute_manifest_on(agent, acl_manifest(target), debug: true) do |result|
          expect(result.stderr).to match(%r{Error:.*The filename, directory name, or volume label syntax is incorrect})
        end
      end
    end
  end
end
