require 'spec_helper_acceptance'

def apply_manifest_and_verify(acl_regex, agent, file_content, mask)
  context "on #{agent}" do
    it 'Execute Manifest' do
      on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(mask, file_content)) do |result|
        assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
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

describe 'File - Allow Mask Specific' do

  def acl_manifest (mask, file_content)
    return <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/allow_#{mask}_rights_file.txt':
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

      acl { 'c:/temp/allow_#{mask}_rights_file.txt':
        permissions  => [
          { identity => '#{user_id}', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  def verify_acl_command(mask)
    "icacls c:/temp/allow_#{mask}_rights_file.txt"
  end

  def verify_content_command(mask)
    "cat /cygdrive/c/temp/allow_#{mask}_rights_file.txt"
  end

  context '"AD, S, WA, X" Rights for Identity on File' do
    mask = '1048868'
    file_content = 'The puppets are controlling my mind!'
    acl_regex = /.*\\bob:\(S,AD,X,WA\)/

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"RD, DE, WEA, RC" Rights for Identity on File' do
    mask = '196625'
    file_content = 'You are never going to feel it!'
    acl_regex = /.*\\bob:\(DE,Rc,RD,WEA\)/

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on File' do
    mask = '1114520'
    file_content = 'Karate time!'
    acl_regex = /.*\\bob:\(D,REA,WEA,RA,WA\)/

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"S, RA, WA, RC" Rights for Identity on File' do
    mask = '1180032'
    file_content = 'I like shoes made by Canadians.'
    acl_regex = /.*\\bob:\(Rc,S,RA,WA\)/

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end

  context '"WD, REA, RA, S" Rights for Identity on File' do
    mask = '1048714'
    file_content = 'My mind is going... I can feel it.'
    acl_regex = /.*\\bob:\(S,WD,REA,RA\)/

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, mask)
    end
  end
end

