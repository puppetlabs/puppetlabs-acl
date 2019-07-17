require 'spec_helper_acceptance'

describe 'File - Deny' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
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

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{user_id}', perm_type => 'deny', rights => ['#{rights}'] },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }

  let(:verify_content_path) { "#{target_parent}/#{target_file}" }

  context '"execute" Rights for Identity on File' do
    let(:rights) { 'execute' }
    let(:file_content) { 'Smells like teen spirit or body odor.' }
    let(:target_file) { "deny_#{rights}_rights_file.txt" }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(Rc,S,X,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"full" Rights for Identity on File' do
    let(:rights) { 'full' }
    let(:target_file) { "deny_#{rights}_rights_file.txt" }
    let(:file_content) { 'You have to fight for your right to party.' }
    let(:acl_regex) { %r{.*\\bob:\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"modify" Rights for Identity on File' do
    let(:rights) { 'modify' }
    let(:target_file) { "deny_#{rights}_rights_file.txt" }
    let(:file_content) { 'Giant flying space pigs with lasers.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(M\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"read, execute" Rights for Identity on File' do
    let(:rights) { "read','execute" }
    let(:target_file) { 'deny_re_rights_file.txt' }
    let(:file_content) { 'Your forcefield is good, but my teleporting is better.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(RX\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"read" Rights for Identity on File' do
    let(:rights) { 'read' }
    let(:target_file) { "deny_#{rights}_rights_file.txt" }
    let(:file_content) { 'Elvis is king of rock and roll.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(R\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"write, execute" Rights for Identity on File' do
    let(:rights) { "write','execute" }
    let(:target_file) { 'deny_we_rights_file.txt' }
    let(:file_content) { 'Now time for some rocket fuel.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(W,Rc,X,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"write, read" Rights for Identity on File' do
    let(:rights) { "write','read" }
    let(:target_file) { 'deny_wr_rights_file.txt' }
    let(:file_content) { 'I live in a garbage can.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(R,W\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"write, read, execute" Rights for Identity on File' do
    let(:rights) { "write','read','execute" }
    let(:target_file) { 'deny_wre_rights_file.txt' }
    let(:file_content) { 'Flying rats.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(RX,W\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context '"write" Rights for Identity on File' do
    let(:rights) { 'write' }
    let(:target_file) { "deny_#{rights}_rights_file.txt" }
    let(:file_content) { 'Marxist cat wants some of your food.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(W,Rc\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end
end
