provider "github" {
  app_auth {} # Required when using `GITHUB_APP_XXX` environment variables
}

run "main_failed_security_and_analysis" {

  command = plan

  variables {
    name = "terraform-github-repository-test"
    security_and_analysis = {
      advanced_security = {
        status = "enabled"
      }
      secret_scanning = {
        status = "enabled"
      }
      secret_scanning_push_protection = {
        status = "enabled"
      }
    }
  }

  expect_failures = [github_repository.this]

}

run "main_failed_allowed_actions_config" {

  command = plan

  variables {
    name            = "terraform-github-repository-test"
    allowed_actions = "all"
    allowed_actions_config = {
      github_owned_allowed = true
      patterns_allowed     = ["hashicorp/*"]
    }
  }

  expect_failures = [github_actions_repository_permissions.this]

}

run "main_passed" {

  command = apply

  variables {
    name                   = "terraform-github-repository-test"
    description            = "This is a test repository"
    delete_branch_on_merge = true
    auto_init              = true
    security_and_analysis = {
      secret_scanning = {
        status = "enabled"
      }
      secret_scanning_push_protection = {
        status = "enabled"
      }
    }
    vulnerability_alerts = true
    allow_update_branch  = false
    branch_protections = [
      {
        pattern                         = "main"
        enforce_admins                  = true
        require_conversation_resolution = true
        required_pull_request_reviews = {
          dismiss_stale_reviews           = true
          require_code_owner_reviews      = true
          required_approving_review_count = "1"
        }
      }
    ]
    actions_secrets = [
      {
        secret_name     = "Secret"
        plaintext_value = "Value"
      }
    ]
    branches = [
      {
        branch = "develop"
      }
    ]
    files = [
      {
        file    = "main.tf"
        content = "# main.tf"
      }
    ]
  }

  assert {
    condition     = length(github_actions_repository_permissions.this) == 0
    error_message = "Actions repository permissions should be empty."
  }

  assert {
    condition     = output.repository != ""
    error_message = "`repository` ouput should not be empty."
  }

  assert {
    condition     = can(regex("^.+/.+$", output.full_name))
    error_message = "`full_name` output should follow pattern \"organization_name/repository_name\"."
  }

  assert {
    condition     = can(regex("^https://github.com/.+/.+$", output.html_url))
    error_message = "`html_url` output should follow pattern \"https://github.com/organization_name/repository_name\"."
  }

  assert {
    condition     = can(regex("^git@github.com:.+/.+\\.git$", output.ssh_clone_url))
    error_message = "`ssh_clone_url` output should follow pattern \"git@github.com:organization_name/repository_name.git\"."
  }

  assert {
    condition     = can(regex("^https://github.com/.+/.+\\.git$", output.http_clone_url))
    error_message = "`http_clone_url` output should follow pattern \"https://github.com/organization_name/repository_name.git\"."
  }

  assert {
    condition     = can(regex("^git://github.com/.+/.+\\.git$", output.git_clone_url))
    error_message = "`git_clone_url` output should follow pattern git://github.com/organization_name/repository_name.git."
  }

  assert {
    condition     = can(regex("^https://github.com/.+/.+$", output.svn_url))
    error_message = "`svn_url` output should follow pattern \"https://github.com/organization_name/repository_name\"."
  }

  assert {
    condition     = output.node_id != ""
    error_message = "`node_id` output should not be empty."
  }

  assert {
    condition     = output.repo_id != ""
    error_message = "`repo_id` output should not be empty."
  }

  assert {
    condition     = length(output.branch_protection) > 0
    error_message = "`branch_protection` output should not be empty."
  }

  assert {
    condition     = length(output.actions_secret) > 0
    error_message = "`actions_secret` output should not be empty."
  }

  assert {
    condition     = alltrue([for secret in output.actions_secret_created_at : can(regex("^\\d{4}-\\d{2}-\\d{2}.*$", secret))])
    error_message = "`actions_secret_created_at` output should not be empty."
  }

  assert {
    condition     = alltrue([for secret in output.actions_secret_updated_at : can(regex("^\\d{4}-\\d{2}-\\d{2}.*$", secret))])
    error_message = "`actions_secret_updated_at` output should not be empty."
  }

  assert {
    condition     = length(output.branches) > 0
    error_message = "`branches` output should not be empty."
  }
  assert {
    condition     = alltrue([for branch in output.branches_source_sha : branch != ""])
    error_message = "`branches_source_sha` should not be empty."
  }
  assert {
    condition     = alltrue([for branch in output.branches_etag : branch != ""])
    error_message = "`branches_etag` should not be empty."
  }

  assert {
    condition     = alltrue([for branch in output.branches_ref : can(regex("^refs/heads/.*$", branch))])
    error_message = "`branches_ref` output should follow pattern \"refs/heads/branch\"."
  }

  assert {
    condition     = alltrue([for branch in output.branches_sha : can(regex("^([a-f0-9]{40})$", branch))])
    error_message = "`branches_sha` output should follow SHA pattern."
  }

  assert {
    condition     = length(output.files) > 0
    error_message = "`files` output should not be empty."
  }

  assert {
    condition     = alltrue([for file in output.files_commit_sha : can(regex("^([a-f0-9]{40})$", file))])
    error_message = "`files_commit_sha` output should follow SHA pattern."
  }

  assert {
    condition     = alltrue([for file in output.files_sha : can(regex("^([a-f0-9]{40})$", file))])
    error_message = "`files_sha` output should follow SHA pattern."
  }

  assert {
    condition     = alltrue([for file in output.files_ref : file != ""])
    error_message = "`files_ref` should not be empty."
  }

}