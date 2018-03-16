require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(acl_regex, agent, file_content, mask)
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(mask, file_content), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(mask)) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(mask)) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'File - Deny Mask Specific' do
  def acl_manifest(mask, file_content)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/deny_#{mask}_rights_file.txt':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { 'c:/temp/deny_#{mask}_rights_file.txt':
        permissions  => [
          { identity => '#{user_id}', perm_type => 'deny', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  def verify_acl_command(mask)
    "icacls c:/temp/deny_#{mask}_rights_file.txt"
  end

  def verify_content_command(mask)
    "cat /cygdrive/c/temp/deny_#{mask}_rights_file.txt"
  end

  context '"AD, S, WA, X" Rights for Identity on File' do
    mask = '1048868'
    file_content = 'Slippery when dry.'
    acl_regex = %r{.*\\bob:\(DENY\)\(S,AD,X,WA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"RD, DE, WEA, RC" Rights for Identity on File' do
    mask = '196625'
    file_content = 'Pressure, oh the pressure.'
    acl_regex = %r{.*\\bob:\(DENY\)\(D,Rc,RD,WEA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on File' do
    mask = '1114520'
    file_content = 'Gallons of hats on your head.'
    acl_regex = %r{.*\\bob:\(DENY\)\(D,REA,WEA,RA,WA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"S, RA, WA, RC" Rights for Identity on File' do
    mask = '1180032'
    file_content = 'We need experienced fighter pilots to train these pigs in the basics of aviation!'
    acl_regex = %r{.*\\bob:\(DENY\)\(Rc,S,RA,WA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"WD, REA, RA, S" Rights for Identity on File' do
    mask = '1048714'
    file_content = 'Tiny little people with small problems.'
    acl_regex = %r{.*\\bob:\(DENY\)\(S,WD,REA,RA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
