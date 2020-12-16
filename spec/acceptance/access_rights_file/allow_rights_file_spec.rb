# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'File - Allow' do
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
          { identity => '#{user_id}', perm_type => 'allow', rights => ['#{rights}'] },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }

  let(:verify_content_path) { "#{target_parent}/#{target_file}" }

  context '"execute" Rights for Identity on File' do
    let(:rights) { 'execute' }
    let(:target_file) { "allow_#{rights}_rights_file.txt" }
    let(:file_content) { 'The bed that eats people. DEATH BED!' }
    let(:acl_regex) { %r{.*\\bob:\(Rc,S,X,RA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"modify" Rights for Identity on File' do
    let(:rights) { 'modify' }
    let(:target_file) { "allow_#{rights}_rights_file.txt" }
    let(:file_content) { 'Snow on the bluff.' }
    let(:acl_regex) { %r{.*\\bob:\(M\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"read, execute" Rights for Identity on File' do
    let(:rights) { "read','execute" }
    let(:target_file) { 'allow_re_rights_file.txt' }
    let(:file_content) { 'Get on the phone with baked beans!' }
    let(:acl_regex) { %r{.*\\bob:\(RX\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"read" Rights for Identity on File' do
    let(:rights) { 'read' }
    let(:target_file) { "allow_#{rights}_rights_file.txt" }
    let(:file_content) { 'Deadly couch eating monster.' }
    let(:acl_regex) { %r{.*\\bob:\(R\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"write, execute" Rights for Identity on File' do
    let(:rights) { "write','execute" }
    let(:target_file) { 'allow_we_rights_file.txt' }
    let(:file_content) { 'Get on the phone with baked beans!' }
    let(:acl_regex) { %r{.*\\bob:\(W,Rc,X,RA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"write, read" Rights for Identity on File' do
    let(:rights) { "write','read" }
    let(:target_file) { 'allow_wr_rights_file.txt' }
    let(:file_content) { 'Mushy bean paste in my eyes!' }
    let(:acl_regex) { %r{.*\\bob:\(R,W\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"write, read, execute" Rights for Identity on File' do
    let(:rights) { "write','read','execute" }
    let(:target_file) { 'allow_wre_rights_file.txt' }
    let(:file_content) { 'Very small feet to eat.' }
    let(:acl_regex) { %r{.*\\bob:\(RX,W\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"write" Rights for Identity on File' do
    let(:rights) { 'write' }
    let(:target_file) { "allow_#{rights}_rights_file.txt" }
    let(:file_content) { 'Smart bubbles in my bath.' }
    let(:acl_regex) { %r{.*\\bob:\(W,Rc\)} }

    include_examples 'execute manifest and verify file'
  end
end
