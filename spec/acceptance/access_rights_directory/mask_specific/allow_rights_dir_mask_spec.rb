require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def execute_manifest_with_mask(acl_regex, agent, mask)
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(mask), debug: true) do |result|
        expect(result.stderr).not_to match(%r{Error:})
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(mask)) do |result|
        expect(result.stdout).to match(%r{#{acl_regex}})
      end
    end
  end
end

describe 'Allow Mask Specific' do
  def acl_manifest(mask)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/allow_#{mask}_rights_dir':
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { 'c:/temp/allow_#{mask}_rights_dir':
        permissions  => [
          { identity => '#{user_id}', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  def verify_acl_command(mask)
    "icacls c:/temp/allow_#{mask}_rights_dir"
  end

  context '"AD, S, WA, X" Rights for Identity on Directory' do
    mask = '1048868'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(S,AD,X,WA\)}

    windows_agents.each do |agent|
      execute_manifest_with_mask(acl_regex, agent, mask)
    end
  end

  context '"RD, DC, WEA, RC" Rights for Identity on Directory' do
    mask = '131153'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(Rc,RD,WEA,DC\)}

    windows_agents.each do |agent|
      execute_manifest_with_mask(acl_regex, agent, mask)
    end
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on Directory' do
    mask = '1114520'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(D,REA,WEA,RA,WA\)}

    windows_agents.each do |agent|
      execute_manifest_with_mask(acl_regex, agent, mask)
    end
  end

  context '"S, RA, WA, RC" Rights for Identity on Directory' do
    mask = '1180032'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(Rc,S,RA,WA\)}

    windows_agents.each do |agent|
      execute_manifest_with_mask(acl_regex, agent, mask)
    end
  end

  context '"WD, REA, RA, S" Rights for Identity on Directory' do
    mask = '1048714'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(S,WD,REA,RA\)}

    windows_agents.each do |agent|
      execute_manifest_with_mask(acl_regex, agent, mask)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
