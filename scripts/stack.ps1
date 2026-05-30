param(
    [ValidateSet("start", "stop", "restart", "logs")]
    [string]$Action = "start",
    [switch]$Build
)

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envFile = Join-Path $root ".env"
$exampleFile = Join-Path $root ".env.example"
$composeFile = Join-Path $root "docker-compose.yml"

if (-not (Test-Path $envFile)) {
    if (Test-Path $exampleFile) {
        Copy-Item -Path $exampleFile -Destination $envFile
        Write-Host "Created .env from .env.example"
    } else {
        throw "Missing .env.example"
    }
}

switch ($Action) {
    "start" {
        if ($Build) {
            docker compose --env-file $envFile -f $composeFile up -d --build
        } else {
            docker compose --env-file $envFile -f $composeFile up -d
        }
    }
    "stop" {
        docker compose --env-file $envFile -f $composeFile down
    }
    "restart" {
        docker compose --env-file $envFile -f $composeFile down
        if ($Build) {
            docker compose --env-file $envFile -f $composeFile up -d --build
        } else {
            docker compose --env-file $envFile -f $composeFile up -d
        }
    }
    "logs" {
        docker compose --env-file $envFile -f $composeFile logs -f --tail 200
    }
}
