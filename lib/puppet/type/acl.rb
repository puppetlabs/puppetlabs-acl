Puppet::Type.newtype(:acl) do
  require 'puppet/type/acl/ace'

  @doc = <<-'EOT'
    Manages access control lists.  The `acl` type is typically
    used when you need more complex management of permissions
    e.g. Windows.

    Sample usage:

      ADD HERE LATER
  EOT

  ensurable

  feature :ace_order_required, "The provider determines if the order of access control entries (ACE) is required."
  feature :can_inherit_parent_permissions, "The provider can inherit permissions from the parent."

  def initialize(*args)
    super

    # if target is unset, use the title
    if self[:target].nil? then
      self[:target] = self[:name]
    end
  end

  newparam(:name) do
    desc "The name of the acl resource. Used for uniqueness. Will set
      to the target if target is unset."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty name must be specified."
      end
    end

    isnamevar
  end

  newparam(:target) do
    desc "The location the acl resource is pointing to. In the first
      release of ACL, this will be a file system location.
      The default is the name."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty target must be specified."
      end
    end
  end

  newparam(:target_type) do
    desc "The type of target for the Acl resource. In the first release
      of ACL, only :file is allowed. Defaults to :file."
    newvalues(:file)
    defaultto(:file)
  end

  newparam(:purge, :boolean => true) do
    desc "Purge specifies whether to remove other explicit permissions
      if not specified in the permissions set. This doesn't do anything
      with permissions inherited from parents. The default is false."
    newvalues(:true, :false)
    defaultto(false)
  end

  newproperty(:permissions, :array_matching => :all) do
    desc "Permissions is an array containing Access Control Entries
      (ACEs). Certain Operating Systems require these ACEs to be in
      explicit order (Windows)."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty permissions must be specified."
      end
    end

    munge do |permission|
      Puppet::Type::Acl::Ace.new(permission)
    end
  end

  newproperty(:owner) do
    desc "The owner identity is also known as a trustee or principal
      that is said to own the particular acl/security descriptor. This
      can be in the form of: 1. User - e.g. 'Bob' or 'TheNet\\Bob',
      2. Group e.g. 'Administrators' or 'BUILTIN\\Administrators', 3.
      SID (Security ID) e.g. 'S-1-5-18'. Defaults to 'S-1-5-32-544'
      (Administrators) on Windows."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty owner must be specified."
      end
    end

    #todo check platform and return specific default - this may not always be windows
    defaultto 'S-1-5-32-544'
  end

  newproperty(:inherit_parent_permissions, :boolean => true) do
    desc "Inherit Parent Permissions specifies whether to inherit
      permissions from parent ACLs or not. The default is true."
    #todo set this based on :can_inherit_parent_permissions
    newvalues(:true,:false)
    defaultto(true)
  end

  validate do
    if self[:permissions] == []
      raise ArgumentError, "Value for permissions should be an array with at least one element specified."
    end
  end
end
