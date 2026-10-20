//! Permission catalogues: `Perm` (tenant) and `PlatformPerm` (staff). Dono alag types:
//! koi function dono ko mix nahi karta, isliye staff perm tenant role ko ya ulta dena type-level par impossible.
//! Single listing macro se enum + `ALL` + `name()` + `from_name()` (naya variant = ek jagah).

macro_rules! catalogue {
    (
        $(#[$meta:meta])*
        $ty:ident { $( $variant:ident = $name:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $ty { $( $variant ),+ }

        impl $ty {
            /// Every permission, in catalogue order (index == discriminant).
            pub const ALL: &'static [$ty] = &[ $( $ty::$variant ),+ ];

            /// Stable dotted name from RBAC.md §4.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $( $ty::$variant => $name ),+ }
            }

            /// Unknown name = `None` (caller must deny, E30).
            #[must_use]
            pub fn from_name(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|p| p.name() == s)
            }

            /// First dotted segment ("reports", "devices", ...).
            #[must_use]
            pub fn section(self) -> &'static str {
                self.name().split('.').next().unwrap_or("")
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

catalogue! {
    /// Tenant permission catalogue (RBAC.md §4.1 to §4.9), grouped by area / product.
    Perm {
        // 4.1 Account / self
        ProfileReadSelf = "profile.read_self",
        ProfileUpdateSelf = "profile.update_self",
        ProfileUpdateTimezone = "profile.update_timezone",
        PasswordChangeSelf = "password.change_self",
        MfaManageSelf = "mfa.manage_self",
        SessionsReadSelf = "sessions.read_self",
        SessionsRevokeSelf = "sessions.revoke_self",
        MembersPreferencesManageSelf = "members.preferences.manage_self",
        ActivityReadSelf = "activity.read_self",
        DownloadsHistoryReadSelf = "downloads.history.read_self",
        // 4.2 Members (subusers)
        MembersRead = "members.read",
        MembersReadRolesCatalogue = "members.read_roles_catalogue",
        MembersCreate = "members.create",
        MembersUpdate = "members.update",
        MembersAssignRole = "members.assign_role",
        MembersSetCapabilities = "members.set_capabilities",
        MembersDisable = "members.disable",
        MembersEnable = "members.enable",
        MembersDelete = "members.delete",
        MembersResetPassword = "members.reset_password",
        MembersBulkAssignDepartment = "members.bulk_assign_department",
        MembersTransferResources = "members.transfer_resources",
        TenantOwnershipTransfer = "tenant.ownership.transfer",
        // 4.3 Groups / departments
        GroupsRead = "groups.read",
        GroupsCreate = "groups.create",
        GroupsUpdate = "groups.update",
        GroupsDelete = "groups.delete",
        GroupsManageMembers = "groups.manage_members",
        GroupsAssignAdmin = "groups.assign_admin",
        DepartmentsRead = "departments.read",
        DepartmentsManage = "departments.manage",
        // 4.4 Activity / sessions / performance
        ActivityReadMembers = "activity.read_members",
        SessionsRevokeMembers = "sessions.revoke_members",
        PerformanceRead = "performance.read",
        AuditReadActions = "audit.read_actions",
        PerformanceErasureMetricsRead = "performance.erasure_metrics.read",
        // 4.5 Devices / machines
        DevicesRead = "devices.read",
        DevicesRegister = "devices.register",
        DevicesUpdate = "devices.update",
        DevicesAssign = "devices.assign",
        DevicesRemoteCommand = "devices.remote_command",
        DevicesRemoteWipe = "devices.remote_wipe",
        DevicesDelete = "devices.delete",
        DevicesReadLicenseStatus = "devices.read_license_status",
        DevicesTransfer = "devices.transfer",
        DevicesStatisticsRead = "devices.statistics.read",
        // 4.6 Licences / credits / billing
        LicensesRead = "licenses.read",
        LicensesActivate = "licenses.activate",
        LicensesAllocate = "licenses.allocate",
        LicensesDeactivateDevice = "licenses.deactivate_device",
        LicensesTransfer = "licenses.transfer",
        LicensesSync = "licenses.sync",
        LicensesRenew = "licenses.renew",
        LicensesRevoke = "licenses.revoke",
        LicensesExport = "licenses.export",
        CreditsRead = "credits.read",
        CreditsConsume = "credits.consume",
        CreditsOfflineGrant = "credits.offline_grant",
        OrdersRead = "orders.read",
        InvoicesRead = "invoices.read",
        OrdersInvoiceDownload = "orders.invoice.download",
        BillingManage = "billing.manage",
        // 4.7 Reports (per product)
        ReportsDriveRead = "reports.drive.read",
        ReportsDriveCreate = "reports.drive.create",
        ReportsDiagRead = "reports.diag.read",
        ReportsDiagCreate = "reports.diag.create",
        ReportsFileRead = "reports.file.read",
        ReportsFileCreate = "reports.file.create",
        ReportsCleanerRead = "reports.cleaner.read",
        ReportsCleanerCreate = "reports.cleaner.create",
        ReportsFreezeRead = "reports.freeze.read",
        ReportsFreezeCreate = "reports.freeze.create",
        ReportsAutopilotRead = "reports.autopilot.read",
        ReportsAutopilotCreate = "reports.autopilot.create",
        ReportsExport = "reports.export",
        ReportsBrandingManage = "reports.branding.manage",
        ReportsTransfer = "reports.transfer",
        ReportsArchive = "reports.archive",
        ReportsDriveOfflineUpload = "reports.drive.offline_upload",
        ReportsDiagOfflineUpload = "reports.diag.offline_upload",
        ReportsFileOfflineUpload = "reports.file.offline_upload",
        ReportsCleanerOfflineUpload = "reports.cleaner.offline_upload",
        ReportsFreezeOfflineUpload = "reports.freeze.offline_upload",
        ReportsAutopilotOfflineUpload = "reports.autopilot.offline_upload",
        ReportsDriveStatisticsRead = "reports.drive.statistics.read",
        ReportsDiagStatisticsRead = "reports.diag.statistics.read",
        ReportsFileStatisticsRead = "reports.file.statistics.read",
        ReportsCleanerStatisticsRead = "reports.cleaner.statistics.read",
        ReportsFreezeStatisticsRead = "reports.freeze.statistics.read",
        ReportsAutopilotStatisticsRead = "reports.autopilot.statistics.read",
        ReportsDriveFacetsRead = "reports.drive.facets.read",
        ReportsDiagFacetsRead = "reports.diag.facets.read",
        ReportsFileFacetsRead = "reports.file.facets.read",
        ReportsCleanerFacetsRead = "reports.cleaner.facets.read",
        ReportsFreezeFacetsRead = "reports.freeze.facets.read",
        ReportsAutopilotFacetsRead = "reports.autopilot.facets.read",
        ReportsDriveSubjectsRead = "reports.drive.subjects.read",
        ReportsExportBatch = "reports.export_batch",
        ReportsBrandingRead = "reports.branding.read",
        // 4.8 Product specific: Autopilot (DSAM)
        AutopilotDevicesRead = "autopilot.devices.read",
        AutopilotDevicesImport = "autopilot.devices.import",
        AutopilotDevicesDelete = "autopilot.devices.delete",
        AutopilotRecheck = "autopilot.recheck",
        AutopilotConnectionManage = "autopilot.connection.manage",
        AutopilotUnlockCredentialsSubmit = "autopilot.unlock_credentials.submit",
        AutopilotSettingsManage = "autopilot.settings.manage",
        AutopilotCustomFieldsUpdate = "autopilot.custom_fields.update",
        AutopilotSchedulesRead = "autopilot.schedules.read",
        AutopilotSchedulesManage = "autopilot.schedules.manage",
        AutopilotUemRecheckRun = "autopilot.uem_recheck.run",
        AutopilotUemRecheckRead = "autopilot.uem_recheck.read",
        AutopilotIntuneDeleteDevice = "autopilot.intune.delete_device",
        AutopilotDonorsCreate = "autopilot.donors.create",
        // 4.8 Freeze (DSFZ)
        FreezeEndpointsRead = "freeze.endpoints.read",
        FreezeEndpointsManage = "freeze.endpoints.manage",
        FreezeChatRead = "freeze.chat.read",
        FreezeChatSend = "freeze.chat.send",
        FreezeEndpointsDelete = "freeze.endpoints.delete",
        FreezeReportsRead = "freeze.reports.read",
        FreezeReportsArchive = "freeze.reports.archive",
        // 4.8 System Cleaner (DSSC)
        CleanerRun = "cleaner.run",
        CleanerRedeem = "cleaner.redeem",
        CleanerReportsRead = "cleaner.reports.read",
        CleanerTransactionsRead = "cleaner.transactions.read",
        // 4.8 Downloads, private cloud
        DownloadsRead = "downloads.read",
        PrivateCloudRead = "private_cloud.read",
        PrivateCloudManage = "private_cloud.manage",
        // 4.9 Tenant administration
        TenantSettingsRead = "tenant.settings.read",
        TenantSettingsUpdate = "tenant.settings.update",
        TenantAuditRead = "tenant.audit.read",
        TenantExportData = "tenant.export_data",
        TenantClose = "tenant.close",
    }
}

catalogue! {
    /// Platform (staff only) permissions, RBAC.md §4.10. Tenant roles ke paas kabhi nahi.
    PlatformPerm {
        TenantsRead = "platform.tenants.read",
        TenantsSuspend = "platform.tenants.suspend",
        FeaturesToggle = "platform.features.toggle",
        QuotasUpdate = "platform.quotas.update",
        StaffAccessOpen = "platform.staff_access.open",
        MembersSupport = "platform.members.support",
        LicensesIssue = "platform.licenses.issue",
        CreditsAdjust = "platform.credits.adjust",
        Refunds = "platform.refunds",
        CheckoutLinksManage = "platform.checkout_links.manage",
        WebhooksManage = "platform.webhooks.manage",
        LeadsRead = "platform.leads.read",
        LeadsManage = "platform.leads.manage",
        ReleasesManage = "platform.releases.manage",
        AuditRead = "platform.audit.read",
        KeysRotate = "platform.keys.rotate",
        TenantErase = "platform.tenant.erase",
        StaffManage = "platform.staff.manage",
        // 4.12 platform additions
        CleanerCodesMint = "platform.cleaner_codes.mint",
        AutopilotCredits = "platform.autopilot.credits",
        ProviderProductsManage = "platform.provider_products.manage",
        EmailLogsRead = "platform.email_logs.read",
        DownloadsRead = "platform.downloads.read",
        ReportsRevoke = "platform.reports.revoke",
        HealthDetailed = "platform.health.detailed",
    }
}
