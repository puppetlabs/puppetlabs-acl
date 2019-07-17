shared_examples 'execute manifest' do |agent, remove = false, file_verify = false|
  it 'applies manifest' do
    execute_manifest_on(agent, acl_manifest, debug: true) do |result|
      expect(result.stderr).not_to match(%r{Error:})
    end
  end

  it 'verifies ACL rights' do
    on(agent, verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  if remove
    it 'applies remove manifest' do
      execute_manifest_on(agent, acl_manifest_remove, debug: true) do |result|
        expect(result.stderr).not_to match(%r{Error:})
      end
    end

    it 'verifies ACL rights' do
      on(agent, verify_acl_command) do |result|
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

shared_examples 'execute manifest and verify file' do |agent|
  it 'applies manifest' do
    execute_manifest_on(agent, acl_manifest, debug: true) do |result|
      expect(result.stderr).not_to match(%r{Error:})
    end
  end

  it 'verifies ACL rights' do
    on(agent, verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  it 'verifies file data integrity' do
    expect(file(verify_content_path)).to be_file
    expect(file(verify_content_path).content).to match(%r{#{file_content}})
  end
end

shared_examples 'execute manifest and verify (with PowerShell)' do |agent|
  it 'applies manifest' do
    execute_manifest_on(agent, acl_manifest, debug: true) do |result|
      expect(result.stderr).not_to match(%r{Error:})
    end
  end

  it 'verifies ACL rights' do
    on(agent, powershell(verify_acl_command, 'EncodedCommand' => true)) do |result|
      expect(result.stdout).to match(acl_regex)
    end
  end
end

shared_examples 'execute manifest and verify child' do |agent|
  it 'applies manifest' do
    execute_manifest_on(agent, acl_manifest, debug: true) do |result|
      expect(result.stderr).not_to match(%r{Error:})
    end
  end

  it 'verifies ACL rights' do
    on(agent, verify_acl_command) do |result|
      expect(result.stdout).to match(%r{#{acl_regex}})
    end
  end

  it 'verifies child ACL rights' do
    on(agent, verify_child_acl_command) do |result|
      expect(result.stdout).not_to match(%r{#{acl_regex}})
    end
  end
end
