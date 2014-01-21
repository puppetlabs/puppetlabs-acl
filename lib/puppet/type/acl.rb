require 'puppet/parameter/boolean'
require 'puppet/type/data/ace'

Puppet::Type.newtype(:acl) do
  @doc = <<-'EOT'
    Manages access control lists.  The `acl` type is typically
    used in when you need more complex management of permissions
    e.g. windows.

    Sample usage:

      ADD HERE LATER
  EOT

  ensurable

  feature :ace_order_required, "The provider determines if the order of access control entries (ACE) is required."
  feature :can_inherit_parent_permissions, "The provider can inherit permissions from the parent."

  @permissions_internal

  def self.permissions_internal
    @permissions_internal
  end

  # def initialize(*args)
  #   super
  #   # Look at what MySQL_grant does here: https://github.com/puppetlabs/puppetlabs-mysql/blob/master/lib/puppet/type/mysql_grant.rb#L8-L20
  #   # convert each permission in permissions to ace
  #   @permissions_internal = []
  #   self[:permissions].each do |permission|
  #     @permissions_internal << Puppet::Type::Data::Ace.new(permission)
  #   end
  # end

  newparam(:name) do
    desc "The name of the acl resource. Used for uniqueness. Will set
      to the target if target is unset."
    isnamevar
  end

  newparam(:target) do
    desc "[Empty for now] The default is the name."
    defaultto ''
  end

  newparam(:purge, :boolean => true, :parent => Puppet::Parameter::Boolean) do
    desc "Purge specifies whether to remove other explicit permissions
      if not specified in the permissions set. This doesn't do anything
      with permissions inherited from parents. The default is false."
    newvalues(:true, :false)
    defaultto(false)
  end

  #newproperty, :array_matching => :all
  newparam(:permissions) do
    desc "Permissions is an array containing Access Control Entries
      (ACEs). Certain Operating Systems require these ACEs to be in
      explicit order (Windows)."
    defaultto []
  end

  #newproperty
  newparam(:owner) do
    desc "The owner identity is also known as a trustee or principal
      that is said to own the particular acl/security descriptor. This
      can be in the form of: 1. User - e.g. 'Bob' or 'TheNet\Bob',
      2. Group e.g. 'Administrators' or 'BUILTIN\Administrators', 3.
      SID (Security ID) e.g. 'S-1-5-18'. Defaults to 'S-1-5-32-544' (Administrators)."
    defaultto 'S-1-5-32-544'
  end

  #newpropery
  newparam(:inherit_parent_permissions, :boolean => true, :parent => Puppet::Parameter::Boolean) do
    desc "Inherit Parent Permissions specifies whether to inherit
      permissions from parent ACLs or not. The default is true."
    defaultto(true)
  end
end
