use bollard::container::ListContainersOptions;
use bollard::Docker;
use common::ContainerInfo;
use std::error::Error;
use std::process::Command;

pub async fn scan_containers() -> Result<Vec<ContainerInfo>, Box<dyn Error>> {
    let mut containers = Vec::new();

    // Попытка подключения к Docker
    if let Ok(docker) = Docker::connect_with_local_defaults() {
        let docker_containers = docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true, // Включаем все контейнеры
                ..Default::default()
            }))
            .await?;

        containers.extend(docker_containers.into_iter().map(|c| {
            ContainerInfo {
                id: c.id.unwrap_or_default(),
                name: c
                    .names
                    .unwrap_or_default()
                    .join(", ")
                    .trim_start_matches('/')
                    .to_string(),
                image: c.image.unwrap_or_default(),
                ports: c
                    .ports
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| format!("{}:{}", p.public_port.unwrap_or(0), p.private_port))
                    .collect(),
                status: c.status.unwrap_or_default(),
                orchestrator: "docker".to_string(),
            }
        }));
    }

    // Попытка подключения к Podman
    let podman_output = Command::new("podman")
        .args(&[
            "ps",
            "-a",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}",
        ])
        .output();

    if let Ok(output) = podman_output {
        let podman_containers = String::from_utf8(output.stdout)?
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                if fields.len() >= 5 {
                    Some(ContainerInfo {
                        id: fields[0].to_string(),
                        name: fields[1].trim_start_matches('/').to_string(),
                        image: fields[2].to_string(),
                        ports: fields[3]
                            .split(',')
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect(),
                        status: fields[4].to_string(),
                        orchestrator: "podman".to_string(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        containers.extend(podman_containers);
    }

    Ok(containers)
}
