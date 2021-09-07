package gatemanpublic

import "fmt"

//ValidateOptions used to validate the options passed to gateman
func ValidateOptions(options ValidateRoleOptions) error {
	for _, role := range options.Role {
		if (role == "admin" || role == "user") && options.Scheme != "Bearer" {
			return fmt.Errorf("invalid auth scheme provided")
		}
		if role == "service" && options.Scheme != options.ServiceAuthScheme {
			return fmt.Errorf("invalid auth scheme provided")
		}

		if (len(options.Role) > 1) && role != options.Data.Role {
			return fmt.Errorf("you do not have permission to call this endpoint")
		}

		if role != "*" && role != options.Data.Role {
			return fmt.Errorf("you do not have permission to call this endpoint")

		}

		for _, service := range options.Service {
			if options.Scheme == options.ServiceAuthScheme {
				if service == "*" {
					return nil
				}
			}
			if service != options.Data.Service {
				return fmt.Errorf("the service: %s does not have permission to call this endpoint", service)
			}

			if (len(options.Service) > 1) && service != options.Data.Service {
				return fmt.Errorf("the service: %s does not have permission to call this endpoint", service)
			}
		}

	}

	return nil
}
