require 'spec_helper_acceptance'

describe 'File - Allow Mask Specific' do
  let(:acl_manifest) do
    <<-MANIFEST
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

  let(:verify_acl_command) { "icacls c:/temp/allow_#{mask}_rights_file.txt" }

  let(:verify_content_path) { "c:\\temp\\allow_#{mask}_rights_file.txt" }

  context '"AD, S, WA, X" Rights for Identity on File' do
    let(:mask) { '1048868' }
    let(:file_content) { 'The puppets are controlling my mind!' }
    let(:acl_regex) { %r{.*\\bob:\(S,AD,X,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"RD, DE, WEA, RC" Rights for Identity on File' do
    let(:mask) { '196625' }
    let(:file_content) { 'You are never going to feel it!' }
    let(:acl_regex) { %r{.*\\bob:\(DE,Rc,RD,WEA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on File' do
    let(:mask) { '1114520' }
    let(:file_content) { 'Karate time!' }
    let(:acl_regex) { %r{.*\\bob:\(D,REA,WEA,RA,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"S, RA, WA, RC" Rights for Identity on File' do
    let(:mask) { '1180032' }
    let(:file_content) { 'I like shoes made by Canadians.' }
    let(:acl_regex) { %r{.*\\bob:\(Rc,S,RA,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"WD, REA, RA, S" Rights for Identity on File' do
    let(:mask) { '1048714' }
    let(:file_content) { 'My mind is going... I can feel it.' }
    let(:acl_regex) { %r{.*\\bob:\(S,WD,REA,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end
end
