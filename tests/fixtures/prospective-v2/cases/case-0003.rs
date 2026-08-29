pub fn allowed(request_tenant: &str, row_tenant: &str) -> bool {
    !request_tenant.is_empty() && !row_tenant.is_empty()
}
