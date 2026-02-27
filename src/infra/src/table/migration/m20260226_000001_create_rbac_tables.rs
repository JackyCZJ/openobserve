use sea_orm_migration::prelude::*;

use super::m20241227_000001_create_organizations_table::Organizations;

#[derive(DeriveMigrationName)]
pub struct Migration;

const ROLES_ORG_ID_NAME_UNIQUE_IDX: &str = "roles_org_id_name_uidx";
const ROLES_ORGANIZATION_FOREIGN_KEY: &str = "roles_org_id_fk";

const ROLE_PERMISSIONS_ROLE_FOREIGN_KEY: &str = "role_permissions_role_id_fk";
const ROLE_PERMISSIONS_RESOURCE_IDX: &str = "role_permissions_resource_idx";

const PRINCIPAL_ROLE_BINDINGS_ORGANIZATION_FOREIGN_KEY: &str =
    "principal_role_bindings_org_id_fk";
const PRINCIPAL_ROLE_BINDINGS_ROLE_FOREIGN_KEY: &str = "principal_role_bindings_role_id_fk";
const PRINCIPAL_ROLE_BINDINGS_ROLE_ID_IDX: &str = "principal_role_bindings_role_id_idx";

const GROUPS_ORGANIZATION_FOREIGN_KEY: &str = "groups_org_id_fk";
const GROUPS_ORG_ID_NAME_UNIQUE_IDX: &str = "groups_org_id_name_uidx";

const GROUP_MEMBERS_GROUP_FOREIGN_KEY: &str = "group_members_group_id_fk";
const GROUP_MEMBERS_PRINCIPAL_IDX: &str = "group_members_principal_idx";

const RESOURCE_RELATIONS_ORGANIZATION_FOREIGN_KEY: &str = "resource_relations_org_id_fk";
const RESOURCE_RELATIONS_CHILD_IDX: &str = "resource_relations_child_idx";

const API_TOKENS_ORGANIZATION_FOREIGN_KEY: &str = "api_tokens_org_id_fk";
const API_TOKENS_TOKEN_HASH_UNIQUE_IDX: &str = "api_tokens_token_hash_uidx";
const API_TOKENS_PRINCIPAL_IDX: &str = "api_tokens_principal_idx";
const API_TOKENS_EXPIRES_AT_IDX: &str = "api_tokens_expires_at_idx";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// 按依赖顺序创建 RBAC 相关表和索引：先建基础实体（roles/groups），
    /// 再建依赖表（permissions/bindings/members），最后建资源关系与 token 表，
    /// 避免外键引用尚未存在的对象。
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(create_roles_table_statement()).await?;
        manager
            .create_index(create_roles_org_id_name_unique_idx_statement())
            .await?;

        manager
            .create_table(create_role_permissions_table_statement())
            .await?;
        manager
            .create_index(create_role_permissions_resource_idx_statement())
            .await?;

        manager
            .create_table(create_principal_role_bindings_table_statement())
            .await?;
        manager
            .create_index(create_principal_role_bindings_role_id_idx_statement())
            .await?;

        manager.create_table(create_groups_table_statement()).await?;
        manager
            .create_index(create_groups_org_id_name_unique_idx_statement())
            .await?;

        manager
            .create_table(create_group_members_table_statement())
            .await?;
        manager
            .create_index(create_group_members_principal_idx_statement())
            .await?;

        manager
            .create_table(create_resource_relations_table_statement())
            .await?;
        manager
            .create_index(create_resource_relations_child_idx_statement())
            .await?;

        manager
            .create_table(create_api_tokens_table_statement())
            .await?;
        manager
            .create_index(create_api_tokens_token_hash_unique_idx_statement())
            .await?;
        manager
            .create_index(create_api_tokens_principal_idx_statement())
            .await?;
        manager
            .create_index(create_api_tokens_expires_at_idx_statement())
            .await?;

        Ok(())
    }

    /// 以与 `up` 相反的顺序回滚，先删索引再删表，优先清理依赖方，
    /// 这样可以在包含外键约束的数据库里稳定回退。
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(API_TOKENS_EXPIRES_AT_IDX)
                    .table(ApiTokens::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name(API_TOKENS_PRINCIPAL_IDX)
                    .table(ApiTokens::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name(API_TOKENS_TOKEN_HASH_UNIQUE_IDX)
                    .table(ApiTokens::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ApiTokens::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(RESOURCE_RELATIONS_CHILD_IDX)
                    .table(ResourceRelations::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ResourceRelations::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(GROUP_MEMBERS_PRINCIPAL_IDX)
                    .table(GroupMembers::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(GroupMembers::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(GROUPS_ORG_ID_NAME_UNIQUE_IDX)
                    .table(Groups::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Groups::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(PRINCIPAL_ROLE_BINDINGS_ROLE_ID_IDX)
                    .table(PrincipalRoleBindings::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(PrincipalRoleBindings::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(ROLE_PERMISSIONS_RESOURCE_IDX)
                    .table(RolePermissions::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(RolePermissions::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(ROLES_ORG_ID_NAME_UNIQUE_IDX)
                    .table(Roles::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Roles::Table).to_owned())
            .await?;

        Ok(())
    }
}

/// 创建 `roles` 表，承载组织内自定义/系统角色元数据。
/// 通过 `(org_id, name)` 唯一索引保证同组织下角色名不重复。
fn create_roles_table_statement() -> TableCreateStatement {
    Table::create()
        .table(Roles::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(Roles::Id)
                .char_len(27)
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(Roles::OrgId).string_len(256).not_null())
        .col(ColumnDef::new(Roles::Name).string_len(128).not_null())
        .col(ColumnDef::new(Roles::Description).text().null())
        .col(
            ColumnDef::new(Roles::IsSystem)
                .boolean()
                .not_null()
                .default(false),
        )
        .col(ColumnDef::new(Roles::CreatedBy).string_len(256).null())
        .col(ColumnDef::new(Roles::CreatedAt).big_integer().not_null())
        .col(ColumnDef::new(Roles::UpdatedAt).big_integer().not_null())
        .foreign_key(
            ForeignKey::create()
                .name(ROLES_ORGANIZATION_FOREIGN_KEY)
                .from(Roles::Table, Roles::OrgId)
                .to(Organizations::Table, Organizations::Identifier),
        )
        .to_owned()
}

/// 创建 `roles(org_id, name)` 唯一索引，支持按组织快速查角色并避免重名。
fn create_roles_org_id_name_unique_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(ROLES_ORG_ID_NAME_UNIQUE_IDX)
        .table(Roles::Table)
        .col(Roles::OrgId)
        .col(Roles::Name)
        .unique()
        .to_owned()
}

/// 创建 `role_permissions` 表，用于定义“角色在某资源上的动作权限”。
/// 主键采用 `(role_id, resource_type, resource_id, action)`，天然避免重复授权行。
fn create_role_permissions_table_statement() -> TableCreateStatement {
    Table::create()
        .table(RolePermissions::Table)
        .if_not_exists()
        .col(ColumnDef::new(RolePermissions::RoleId).char_len(27).not_null())
        .col(
            ColumnDef::new(RolePermissions::ResourceType)
                .string_len(128)
                .not_null(),
        )
        .col(
            ColumnDef::new(RolePermissions::ResourceId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(RolePermissions::Action)
                .string_len(32)
                .not_null(),
        )
        .col(
            ColumnDef::new(RolePermissions::Effect)
                .small_integer()
                .not_null()
                .default(1),
        )
        .col(ColumnDef::new(RolePermissions::Condition).json().null())
        .col(ColumnDef::new(RolePermissions::CreatedAt).big_integer().not_null())
        .primary_key(
            Index::create()
                .col(RolePermissions::RoleId)
                .col(RolePermissions::ResourceType)
                .col(RolePermissions::ResourceId)
                .col(RolePermissions::Action),
        )
        .foreign_key(
            ForeignKey::create()
                .name(ROLE_PERMISSIONS_ROLE_FOREIGN_KEY)
                .from(RolePermissions::Table, RolePermissions::RoleId)
                .to(Roles::Table, Roles::Id)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .to_owned()
}

/// 创建资源维度索引，优化“按资源反查有哪些权限规则”的读路径。
fn create_role_permissions_resource_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(ROLE_PERMISSIONS_RESOURCE_IDX)
        .table(RolePermissions::Table)
        .col(RolePermissions::ResourceType)
        .col(RolePermissions::ResourceId)
        .col(RolePermissions::Action)
        .to_owned()
}

/// 创建 `principal_role_bindings` 表，存储主体（用户/服务账号/组）到角色的绑定关系。
/// 通过复合主键保证同一主体不会重复绑定到同一角色。
fn create_principal_role_bindings_table_statement() -> TableCreateStatement {
    Table::create()
        .table(PrincipalRoleBindings::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(PrincipalRoleBindings::OrgId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(PrincipalRoleBindings::PrincipalType)
                .string_len(32)
                .not_null(),
        )
        .col(
            ColumnDef::new(PrincipalRoleBindings::PrincipalId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(PrincipalRoleBindings::RoleId)
                .char_len(27)
                .not_null(),
        )
        .col(
            ColumnDef::new(PrincipalRoleBindings::CreatedBy)
                .string_len(256)
                .null(),
        )
        .col(
            ColumnDef::new(PrincipalRoleBindings::CreatedAt)
                .big_integer()
                .not_null(),
        )
        .primary_key(
            Index::create()
                .col(PrincipalRoleBindings::OrgId)
                .col(PrincipalRoleBindings::PrincipalType)
                .col(PrincipalRoleBindings::PrincipalId)
                .col(PrincipalRoleBindings::RoleId),
        )
        .foreign_key(
            ForeignKey::create()
                .name(PRINCIPAL_ROLE_BINDINGS_ORGANIZATION_FOREIGN_KEY)
                .from(PrincipalRoleBindings::Table, PrincipalRoleBindings::OrgId)
                .to(Organizations::Table, Organizations::Identifier),
        )
        .foreign_key(
            ForeignKey::create()
                .name(PRINCIPAL_ROLE_BINDINGS_ROLE_FOREIGN_KEY)
                .from(PrincipalRoleBindings::Table, PrincipalRoleBindings::RoleId)
                .to(Roles::Table, Roles::Id)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .to_owned()
}

/// 创建 `role_id` 索引，优化“查某角色下有哪些主体”的场景。
fn create_principal_role_bindings_role_id_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(PRINCIPAL_ROLE_BINDINGS_ROLE_ID_IDX)
        .table(PrincipalRoleBindings::Table)
        .col(PrincipalRoleBindings::RoleId)
        .to_owned()
}

/// 创建 `groups` 表，支持组织内主体聚合管理。
/// 通过 `(org_id, name)` 唯一索引保证组名在组织内唯一。
fn create_groups_table_statement() -> TableCreateStatement {
    Table::create()
        .table(Groups::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(Groups::Id)
                .char_len(27)
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(Groups::OrgId).string_len(256).not_null())
        .col(ColumnDef::new(Groups::Name).string_len(128).not_null())
        .col(ColumnDef::new(Groups::Description).text().null())
        .col(ColumnDef::new(Groups::CreatedBy).string_len(256).null())
        .col(ColumnDef::new(Groups::CreatedAt).big_integer().not_null())
        .col(ColumnDef::new(Groups::UpdatedAt).big_integer().not_null())
        .foreign_key(
            ForeignKey::create()
                .name(GROUPS_ORGANIZATION_FOREIGN_KEY)
                .from(Groups::Table, Groups::OrgId)
                .to(Organizations::Table, Organizations::Identifier),
        )
        .to_owned()
}

/// 创建 `groups(org_id, name)` 唯一索引，避免同组织下组名冲突。
fn create_groups_org_id_name_unique_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(GROUPS_ORG_ID_NAME_UNIQUE_IDX)
        .table(Groups::Table)
        .col(Groups::OrgId)
        .col(Groups::Name)
        .unique()
        .to_owned()
}

/// 创建 `group_members` 表，记录组成员关系。
/// 主键采用 `(group_id, principal_type, principal_id)` 以防止重复加组。
fn create_group_members_table_statement() -> TableCreateStatement {
    Table::create()
        .table(GroupMembers::Table)
        .if_not_exists()
        .col(ColumnDef::new(GroupMembers::GroupId).char_len(27).not_null())
        .col(
            ColumnDef::new(GroupMembers::PrincipalType)
                .string_len(32)
                .not_null(),
        )
        .col(
            ColumnDef::new(GroupMembers::PrincipalId)
                .string_len(256)
                .not_null(),
        )
        .col(ColumnDef::new(GroupMembers::AddedBy).string_len(256).null())
        .col(ColumnDef::new(GroupMembers::CreatedAt).big_integer().not_null())
        .primary_key(
            Index::create()
                .col(GroupMembers::GroupId)
                .col(GroupMembers::PrincipalType)
                .col(GroupMembers::PrincipalId),
        )
        .foreign_key(
            ForeignKey::create()
                .name(GROUP_MEMBERS_GROUP_FOREIGN_KEY)
                .from(GroupMembers::Table, GroupMembers::GroupId)
                .to(Groups::Table, Groups::Id)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .to_owned()
}

/// 创建成员反查索引，支持从主体快速定位其加入的组。
fn create_group_members_principal_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(GROUP_MEMBERS_PRINCIPAL_IDX)
        .table(GroupMembers::Table)
        .col(GroupMembers::PrincipalType)
        .col(GroupMembers::PrincipalId)
        .to_owned()
}

/// 创建 `resource_relations` 表，描述资源之间的层级/关联关系（如 folder -> dashboard）。
/// 复合主键确保相同关系边不会重复写入。
fn create_resource_relations_table_statement() -> TableCreateStatement {
    Table::create()
        .table(ResourceRelations::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(ResourceRelations::OrgId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(ResourceRelations::ParentType)
                .string_len(128)
                .not_null(),
        )
        .col(
            ColumnDef::new(ResourceRelations::ParentId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(ResourceRelations::ChildType)
                .string_len(128)
                .not_null(),
        )
        .col(
            ColumnDef::new(ResourceRelations::ChildId)
                .string_len(256)
                .not_null(),
        )
        .col(
            ColumnDef::new(ResourceRelations::Relation)
                .string_len(64)
                .not_null()
                .default("contains"),
        )
        .col(ColumnDef::new(ResourceRelations::CreatedBy).string_len(256).null())
        .col(
            ColumnDef::new(ResourceRelations::CreatedAt)
                .big_integer()
                .not_null(),
        )
        .primary_key(
            Index::create()
                .col(ResourceRelations::OrgId)
                .col(ResourceRelations::ParentType)
                .col(ResourceRelations::ParentId)
                .col(ResourceRelations::ChildType)
                .col(ResourceRelations::ChildId)
                .col(ResourceRelations::Relation),
        )
        .foreign_key(
            ForeignKey::create()
                .name(RESOURCE_RELATIONS_ORGANIZATION_FOREIGN_KEY)
                .from(ResourceRelations::Table, ResourceRelations::OrgId)
                .to(Organizations::Table, Organizations::Identifier),
        )
        .to_owned()
}

/// 创建子资源维度索引，优化“从子对象向上回溯父资源”的访问路径。
fn create_resource_relations_child_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(RESOURCE_RELATIONS_CHILD_IDX)
        .table(ResourceRelations::Table)
        .col(ResourceRelations::OrgId)
        .col(ResourceRelations::ChildType)
        .col(ResourceRelations::ChildId)
        .to_owned()
}

/// 创建 `api_tokens` 表，统一保存 PAT/Service Token 等鉴权凭据元数据。
/// 其中 `token_type/scopes/expires_at/last_used_at/created_by` 是本次 M3 要求新增的核心字段。
fn create_api_tokens_table_statement() -> TableCreateStatement {
    Table::create()
        .table(ApiTokens::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(ApiTokens::Id)
                .char_len(27)
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(ApiTokens::OrgId).string_len(256).not_null())
        .col(ColumnDef::new(ApiTokens::Name).string_len(128).not_null())
        .col(ColumnDef::new(ApiTokens::TokenHash).string_len(512).not_null())
        .col(ColumnDef::new(ApiTokens::TokenPrefix).string_len(32).null())
        .col(
            ColumnDef::new(ApiTokens::PrincipalType)
                .string_len(32)
                .not_null(),
        )
        .col(
            ColumnDef::new(ApiTokens::PrincipalId)
                .string_len(256)
                .not_null(),
        )
        .col(ColumnDef::new(ApiTokens::TokenType).string_len(32).not_null())
        .col(
            ColumnDef::new(ApiTokens::Scopes)
                .json()
                .not_null()
                .default("[]"),
        )
        .col(ColumnDef::new(ApiTokens::ExpiresAt).big_integer().null())
        .col(ColumnDef::new(ApiTokens::LastUsedAt).big_integer().null())
        .col(ColumnDef::new(ApiTokens::CreatedBy).string_len(256).null())
        .col(ColumnDef::new(ApiTokens::CreatedAt).big_integer().not_null())
        .col(ColumnDef::new(ApiTokens::UpdatedAt).big_integer().not_null())
        .foreign_key(
            ForeignKey::create()
                .name(API_TOKENS_ORGANIZATION_FOREIGN_KEY)
                .from(ApiTokens::Table, ApiTokens::OrgId)
                .to(Organizations::Table, Organizations::Identifier),
        )
        .to_owned()
}

/// 创建 token hash 唯一索引，确保同一个凭据摘要不会重复落库。
fn create_api_tokens_token_hash_unique_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(API_TOKENS_TOKEN_HASH_UNIQUE_IDX)
        .table(ApiTokens::Table)
        .col(ApiTokens::TokenHash)
        .unique()
        .to_owned()
}

/// 创建主体维度索引，优化“按主体列出 token”能力。
fn create_api_tokens_principal_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(API_TOKENS_PRINCIPAL_IDX)
        .table(ApiTokens::Table)
        .col(ApiTokens::OrgId)
        .col(ApiTokens::PrincipalType)
        .col(ApiTokens::PrincipalId)
        .to_owned()
}

/// 创建过期时间索引，便于批量清理即将过期或已过期 token。
fn create_api_tokens_expires_at_idx_statement() -> IndexCreateStatement {
    Index::create()
        .if_not_exists()
        .name(API_TOKENS_EXPIRES_AT_IDX)
        .table(ApiTokens::Table)
        .col(ApiTokens::ExpiresAt)
        .to_owned()
}

#[derive(DeriveIden)]
enum Roles {
    Table,
    Id,
    OrgId,
    Name,
    Description,
    IsSystem,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum RolePermissions {
    Table,
    RoleId,
    ResourceType,
    ResourceId,
    Action,
    Effect,
    Condition,
    CreatedAt,
}

#[derive(DeriveIden)]
enum PrincipalRoleBindings {
    Table,
    OrgId,
    PrincipalType,
    PrincipalId,
    RoleId,
    CreatedBy,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Groups {
    Table,
    Id,
    OrgId,
    Name,
    Description,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum GroupMembers {
    Table,
    GroupId,
    PrincipalType,
    PrincipalId,
    AddedBy,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ResourceRelations {
    Table,
    OrgId,
    ParentType,
    ParentId,
    ChildType,
    ChildId,
    Relation,
    CreatedBy,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ApiTokens {
    Table,
    Id,
    OrgId,
    Name,
    TokenHash,
    TokenPrefix,
    PrincipalType,
    PrincipalId,
    TokenType,
    Scopes,
    ExpiresAt,
    LastUsedAt,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_sql_contains_expected_constraints_and_fields() {
        let roles_unique_idx_sql =
            create_roles_org_id_name_unique_idx_statement().to_string(PostgresQueryBuilder);
        assert!(roles_unique_idx_sql.contains("roles_org_id_name_uidx"));
        assert!(roles_unique_idx_sql.contains("\"org_id\""));
        assert!(roles_unique_idx_sql.contains("\"name\""));

        let api_tokens_sql = create_api_tokens_table_statement().to_string(PostgresQueryBuilder);
        assert!(api_tokens_sql.contains("\"token_type\" varchar(32) NOT NULL"));
        assert!(api_tokens_sql.contains("\"scopes\" json NOT NULL"));
        assert!(api_tokens_sql.contains("\"expires_at\" bigint NULL"));
        assert!(api_tokens_sql.contains("\"last_used_at\" bigint NULL"));
        assert!(api_tokens_sql.contains("\"created_by\" varchar(256) NULL"));

        let token_hash_unique_idx_sql =
            create_api_tokens_token_hash_unique_idx_statement().to_string(PostgresQueryBuilder);
        assert!(token_hash_unique_idx_sql.contains("UNIQUE INDEX"));
        assert!(token_hash_unique_idx_sql.contains("api_tokens_token_hash_uidx"));
        assert!(token_hash_unique_idx_sql.contains("\"token_hash\""));
    }

    #[test]
    fn sqlite_sql_contains_expected_constraints_and_fields() {
        let groups_unique_idx_sql =
            create_groups_org_id_name_unique_idx_statement().to_string(SqliteQueryBuilder);
        assert!(groups_unique_idx_sql.contains("groups_org_id_name_uidx"));
        assert!(groups_unique_idx_sql.contains("\"org_id\""));
        assert!(groups_unique_idx_sql.contains("\"name\""));

        let api_tokens_sql = create_api_tokens_table_statement().to_string(SqliteQueryBuilder);
        assert!(api_tokens_sql.contains("\"token_type\" varchar(32) NOT NULL"));
        assert!(api_tokens_sql.contains("\"scopes\" json_text NOT NULL"));
        assert!(api_tokens_sql.contains("\"expires_at\" bigint NULL"));
        assert!(api_tokens_sql.contains("\"last_used_at\" bigint NULL"));
        assert!(api_tokens_sql.contains("\"created_by\" varchar(256) NULL"));

        let principal_idx_sql =
            create_api_tokens_principal_idx_statement().to_string(SqliteQueryBuilder);
        assert!(principal_idx_sql.contains("api_tokens_principal_idx"));
        assert!(principal_idx_sql.contains("\"org_id\""));
        assert!(principal_idx_sql.contains("\"principal_type\""));
        assert!(principal_idx_sql.contains("\"principal_id\""));
    }
}
