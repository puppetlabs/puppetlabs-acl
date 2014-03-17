require 'puppet/type'
require 'pathname'

Puppet::Type.newtype(:acl) do
  require Pathname.new(__FILE__).dirname + '../../' + 'puppet/type/acl/ace'
  require Pathname.new(__FILE__).dirname + '../../' + 'puppet/type/acl/constants'

  @doc = <<-'EOT'
    Manages access control lists (ACLs).  The `acl` type is
    typically used when you need more complex management of
    permissions e.g. Windows. ACLs typically contain access
    control entries (ACEs) that define a trustee (identity)
    with a set of rights, whether the type is allow or deny,
    and how inheritance and propagation of those ACEs are
    applied to the resource target and child types under it.
    The order that ACEs are listed in is important on Windows
    as it determines what is applied first.

    Order of ACE application on Windows is explicit deny,
    explicit allow, inherited deny, then inherited allow. You
    cannot specify inherited ACEs in a manifest, only whether
    to allow upstream inheritance to flow into the managed
    target location (known as security descriptor). Please
    ensure your modeled resources follow this order or Windows
    will complain. NOTE: `acl` type does not enforce or
    complain about ACE order.

    See examples below to learn about the different features of
    the `acl` type.


    At a minimum, you need to provide the target and at least
    one permission (access control entry or ACE). It will default
    the other settings to sensible defaults.

    Minimally expressed sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        permissions => [
         { identity => 'Administrator', rights => ['full'] },
         { identity => 'Users', rights => ['read','execute'] }
       ],
      }


    If you want you can provide a fully expressed ACL. The
    fully expressed acl in the sample below produces the same
    settings as the minimal sample above.

    Fully expressed sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        target      => 'c:/tempperms',
        target_type => 'file',
        purge       => 'false',
        permissions => [
         { identity => 'Administrator', rights => ['full'], type=> 'allow', child_types => 'all', affects => 'all' },
         { identity => 'Users', rights => ['read','execute'], type=> 'allow', child_types => 'all', affects => 'all' }
        ],
        owner       => 'Administrators', #Creator_Owner specific, doesn't manage unless specified
        group       => 'Users', #Creator_Owner specific, doesn't manage unless specified
        inherit_parent_permissions => 'true',
      }


    Adding in multiple users is done by just adding users to the
    list of permissions. You can also see that you can specify
    Domain qualified users and SIDs if you need to.

    Multi-user sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'NT AUTHORITY\SYSTEM', rights => ['modify'] },
         { identity => 'BUILTIN\Users', rights => ['read','execute'] },
         { identity => 'S-1-5-32-544', rights => ['write','read','execute'] }
        ],
        inherit_parent_permissions => 'false',
      }


    You can manage the same target across multiple acl
    resources with some caveats. The title of the resource
    needs to be unique. It is suggested that you only do
    this when you would need to (can get confusing). You should
    not set purge => 'true' on any of the resources that apply
    to the same target or you will see thrashing in reports as
    the permissions will be added and removed every catalog
    application. Use this feature with care.

    Manage same ACL resource multiple acls sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        permissions => [
         { identity => 'Administrator', rights => ['full'] }
       ],
      }

      acl { 'tempperms_Users':
        ensure      => present,,
        target      => 'c:/tempperms',
        permissions => [
         { identity => 'Users', rights => ['read','execute'] }
       ],
      }


    Removing upstream inheritance is known as "protecting" the
    target. When an item is "protected" without purge => true,
    the inherited ACEs will be copied into the target as
    unmanaged ACEs.

    Protected ACL sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        permissions => [
         { identity => 'Administrators', rights => ['full'] },
         { identity => 'Users', rights => ['full'] }
        ],
        inherit_parent_permissions => 'false',
      }


    To lock down a folder to managed explicit ACEs, you want to
    set purge => true. This will only remove other explicit ACEs
    from the folder that are unmanaged by this resource. All
    inherited ACEs will remain (see next example).

    Purge sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'Administrators', rights => ['full'] },
         { identity => 'Users', rights => ['full'] }
        ],
        inherit_parent_permissions => 'false',
      }


    To lock down a folder to only the permissions specified in
    the manifest resource, you want to protect the folder and set
    purge => 'true'. This ensure that the only permissions on the
    folder are the ones that you have set explicitly in the
    manifest.

    Protected with purge sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'Administrators', rights => ['full'] },
         { identity => 'Users', rights => ['full'] }
        ],
        inherit_parent_permissions => 'false',
      }


    ACEs can be of type 'allow' (default) or 'deny'. Deny ACEs
    should be listed first before allow ACEs.

    Deny ACE sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        permissions => [
         { identity => 'SYSTEM', rights => ['full'], type=> 'deny', affects => 'self_only' },
         { identity => 'Administrators', rights => ['full'] }
        ],
      }


    ACEs have inheritance structures as well aka "child_types":
    'all' (default), 'none', 'containers', and 'objects'. This
    controls how sub-folders and files will inherit each
    particular ACE.

    ACE inheritance "child_types" sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'SYSTEM', rights => ['full'], child_types => 'all' },
         { identity => 'Administrators', rights => ['full'], child_types => 'containers' },
         { identity => 'Administrator', rights => ['full'], child_types => 'objects' },
         { identity => 'Users', rights => ['full'], child_types => 'none' }
        ],
        inherit_parent_permissions => 'false',
      }


    ACEs have propagation rules, a nice way of saying "how" they
    apply permissions to containers, objects, children and
    grandchildren. Propagation aka "affects" can take the value
    of: 'all' (default), 'self_only', 'children_only',
    'direct_children_only', and 'self_and_direct_children_only'.

    ACE propagation "affects" sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'Administrators', rights => ['modify'], affects => 'all' },
         { identity => 'Administrators', rights => ['full'], affects => 'self_only' },
         { identity => 'Administrator', rights => ['full'], affects => 'direct_children_only' },
         { identity => 'Users', rights => ['full'], affects => 'children_only' },
         { identity => 'Authenticated Users', rights => ['read'], affects => 'self_and_direct_children_only' }
        ],
        inherit_parent_permissions => 'false',
      }


    An interesting note with Windows, you can specify the same
    identity with different inheritance and propagation and each
    of those items will actually be managed as separate ACEs.

    Same user multiple ACEs sample usage:

      acl { 'c:/tempperms':
        ensure      => present,
        purge       => 'true',
        permissions => [
         { identity => 'SYSTEM', rights => ['modify'], child_types => 'none' },
         { identity => 'SYSTEM', rights => ['modify'], child_types => 'containers' },
         { identity => 'SYSTEM', rights => ['modify'], child_types => 'objects' },
         { identity => 'SYSTEM', rights => ['full'], affects => 'self_only' },
         { identity => 'SYSTEM', rights => ['read','execute'], affects => 'direct_children_only' },
         { identity => 'SYSTEM', rights => ['read','execute'], child_types=>'containers', affects => 'direct_children_only' },
         { identity => 'SYSTEM', rights => ['read','execute'], child_types=>'objects', affects => 'direct_children_only' },
         { identity => 'SYSTEM', rights => ['full'], affects => 'children_only' },
         { identity => 'SYSTEM', rights => ['full'], child_types=>'containers', affects => 'children_only' },
         { identity => 'SYSTEM', rights => ['full'], child_types=>'objects', affects => 'children_only' },
         { identity => 'SYSTEM', rights => ['read'], affects => 'self_and_direct_children_only' },
         { identity => 'SYSTEM', rights => ['read'], child_types=>'containers', affects => 'self_and_direct_children_only' },
         { identity => 'SYSTEM', rights => ['read'], child_types=>'objects', affects => 'self_and_direct_children_only' }
        ],
        inherit_parent_permissions => 'false',
      }
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

    if self[:owner].nil? then
      self[:owner] = Puppet::Type::Acl::Constants::OWNER_UNSPECIFIED
    end

    if self[:group].nil? then
      self[:group] = Puppet::Type::Acl::Constants::GROUP_UNSPECIFIED
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
      explicit order (Windows). Every element in the array is a hash
      that will at the very least need `identity` and `rights` e.g
      { identity => 'Administrators', rights => ['full'] } and at the
      very most can include `type`, `child_types`, `affects`, and
      `mask` (mask only should be with `rights => ['mask_specific']`)
      e.g. `{ identity => 'Administrators', rights => ['full'],
      type=> 'allow', child_types => 'all', affects => 'all' }`.
      `Identity` is a group, user or ID (SID on Windows). The identity must
      exist on the system and will auto-require on user resources.
      `Rights` is an array that contains 'full', 'modify', 'mask_specific'
      or some combination of 'write', 'read', and 'execute'. If you specify
      'mask_specific' you must also specify `mask` with an integer (passed
      as a string) that represents the permissions mask. `Type` is
      represented as 'allow' (default) or 'deny'. `Child_types` determines
      how an ACE is inherited downstream from the target. Valid values are
      'all' (default), 'objects', 'containers' or 'none'. `Affects` determines
      how the downstream inheritance is propagated. Valid values are
      'all' (default), 'self_only', 'children_only',
      'self_and_direct_children_only' or 'direct_children_only'."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty permissions must be specified."
      end
      if value['inherited']
        raise ArgumentError,
         "Puppet can not manage inherited ACEs.
         If you used puppet resource acl to build your manifest, please remove
         any inherited => true entries in permissions when adding the resource
         to the manifest.
         Reference: #{value.inspect}"
      end
    end

    munge do |permission|
      Puppet::Type::Acl::Ace.new(permission, provider)
    end

    def insync?(current)
      if provider.respond_to?(:permissions_insync?)
        return provider.permissions_insync?(current, @should)
      end

      super(current)
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:permissions_to_s)
        return provider.permissions_to_s(currentvalue)
      end

      super(currentvalue)
    end
    alias :should_to_s :is_to_s
  end

  newproperty(:owner) do
    desc "The owner identity is also known as a trustee or principal
      that is said to own the particular acl/security descriptor. This
      can be in the form of: 1. User - e.g. 'Bob' or 'TheNet\\Bob',
      2. Group e.g. 'Administrators' or 'BUILTIN\\Administrators', 3.
      SID (Security ID) e.g. 'S-1-5-18'. Defaults to not specified on
      Windows. This allows owner to stay set to whatever it is currently
      set to (owner can vary depending on the original CREATOR OWNER).
      The trustee must exist on the system and will auto-require on user
      resources."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty owner must be specified."
      end
    end

    def insync?(current)
      return true if should == Puppet::Type::Acl::Constants::OWNER_UNSPECIFIED

      if provider.respond_to?(:owner_insync?)
        return provider.owner_insync?(current, should)
      end

      super(current)
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:owner_to_s)
        return provider.owner_to_s(currentvalue)
      end

      super(currentvalue)
    end
    alias :should_to_s :is_to_s
  end

  newproperty(:group) do
    desc "The group identity is also known as a trustee or principal
      that is said to have access to the particular acl/security descriptor.
      This can be in the form of: 1. User - e.g. 'Bob' or 'TheNet\\Bob',
      2. Group e.g. 'Administrators' or 'BUILTIN\\Administrators', 3.
      SID (Security ID) e.g. 'S-1-5-18'. Defaults to not specified on
      Windows. This allows group to stay set to whatever it is currently
      set to (group can vary depending on the original CREATOR OWNER).
      The trustee must exist on the system and will auto-require on user
      resources."

    validate do |value|
      if value.nil? or value.empty?
        raise ArgumentError, "A non-empty group must be specified."
      end
    end

    def insync?(current)
      return true if should == Puppet::Type::Acl::Constants::GROUP_UNSPECIFIED

      if provider.respond_to?(:group_insync?)
        return provider.group_insync?(current, should)
      end

      super(current)
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:group_to_s)
        return provider.group_to_s(currentvalue)
      end

      super(currentvalue)
    end
    alias :should_to_s :is_to_s
  end

  newproperty(:inherit_parent_permissions, :boolean => true) do
    desc "Inherit Parent Permissions specifies whether to inherit
      permissions from parent ACLs or not. The default is true."
    #todo v2 set this based on :can_inherit_parent_permissions
    newvalues(:true,:false)
    defaultto(true)

    def insync?(current)
      super(resource.munge_boolean(current))
    end
  end

  validate do
    if self[:permissions] == []
      raise ArgumentError, "Value for permissions should be an array with at least one element specified."
    end
  end

  autorequire(:file) do
    # review - autorequire is a soft dependency, is it a waste of cycles to attempt to find one versus just soft require?
    required_file = []
    if self[:target] && self[:target_type] == :file
      target_path = File.expand_path(self[:target]).to_s

      if file_resource = catalog.resource(:file, target_path)
        required_file << file_resource.to_s
      end

      if required_file.empty?
        # There is a bug with the casing on the volume (c:/ versus C:/) causing resources to not be found by the catalog
        #  checking against lowercase and uppercase corrects that.
        target_path[0] = target_path[0].downcase
        unless file_resource = catalog.resource(:file, target_path)
          target_path[0] = target_path[0].upcase
          file_resource = catalog.resource(:file, target_path)
        end
        required_file << file_resource.to_s if file_resource
      end
    end

    required_file
  end

  autorequire(:user) do
    required_users = []

    unless provider.respond_to?(:get_account_name)
      return_same_value = lambda { |current_value| return current_value}
      provider.class.send(:define_method,'get_account_name', &return_same_value)
    end

    unless self[:owner] == Puppet::Type::Acl::Constants::OWNER_UNSPECIFIED
      owner_name = provider.get_account_name(self[:owner])

      # add both qualified and unqualified items
      required_users << "User[#{self[:owner]}]"
      required_users << "User[#{owner_name}]"
    end

    unless self[:group] == Puppet::Type::Acl::Constants::GROUP_UNSPECIFIED
      group_name = provider.get_account_name(self[:group])

      # add both qualified and unqualified items
      required_users << "User[#{self[:group]}]"
      required_users << "User[#{group_name}]"
    end

    permissions = self[:permissions]
    unless permissions.nil?
      permissions.each do |permission|
        account_name = provider.get_account_name(permission.identity)
        required_users << "User[#{permission.identity}]"
        required_users << "User[#{account_name}]"
      end
    end

    required_users.uniq
  end

  #todo v2? autorequire group

  def munge_boolean(value)
    case value
      when true, "true", :true
        :true
      when false, "false", :false
        :false
      else
        fail("munge_boolean only takes booleans")
    end
  end
end
