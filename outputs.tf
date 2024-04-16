output "cluster_names" {
    value = [
        local.scenario_three,
        local.scenario_two,
        local.scenario_one
    ]
}

output "region" {
    value   = local.region
}