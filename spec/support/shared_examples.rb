# frozen_string_literal: true

shared_examples 'execute manifest' do |remove = false, file_verify = false|
  it 'applies manifest' do
    # acl_idempotent_apply(acl_manifest)
    apply_manifest(acl_manifest, catch_failures: true)
  end

  it 'verifies ACL rights' do
    run_shell(verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  if remove
    it 'applies remove manifest' do
      apply_manifest(acl_manifest_remove, catch_failures: true)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).not_to match(%r{#{acl_regex}})
      end
    end
  end

  if file_verify
    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end

shared_examples 'execute manifest and verify file' do
  it 'applies manifest' do
    # acl_idempotent_apply(acl_manifest)
    apply_manifest(acl_manifest, catch_failures: true)
  end

  it 'verifies ACL rights' do
    run_shell(verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  it 'verifies file data integrity' do
    expect(file(verify_content_path)).to be_file
    expect(file(verify_content_path).content).to match(%r{#{file_content}})
  end
end

shared_examples 'execute manifest and verify (with PowerShell)' do
  it 'applies manifest' do
    # acl_idempotent_apply(acl_manifest)
    apply_manifest(acl_manifest, catch_failures: true)
  end

  it 'verifies ACL rights' do
    run_shell(powershell(verify_acl_command, 'EncodedCommand' => true)) do |result|
      expect(result.stdout.strip).to match(acl_regex)
    end
  end
end

shared_examples 'execute manifest and verify child' do
  it 'applies manifest' do
    # acl_idempotent_apply(acl_manifest)
    apply_manifest(acl_manifest, catch_failures: true)
  end

  it 'verifies ACL rights' do
    run_shell(verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  it 'verifies child ACL rights' do
    run_shell(verify_child_acl_command) do |result|
      expect(result.stdout).not_to match(%r{#{acl_regex}})
    end
  end
end
