# Yuri devcontainer Dockerfile
# Last updated: 2026-02-19

# This Dockerfile sets up a development environment with:
# - Ubuntu 24.04 base image
# - System dependencies for development
# - mise (runtime version manager) for managing Python and Node versions
# - uv (fast Python package manager) for installing Python tools
# - Claude Code (native installation)


FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Install system dependencies in a single layer
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends \
    # Build essentials for native extensions
    build-essential \
    # SSL/crypto libraries
    libssl-dev libffi-dev \
    # Database clients
    sqlite3 mysql-client postgresql-client \
    # Python build dependencies
    libbz2-dev libreadline-dev libsqlite3-dev \
    zlib1g-dev liblzma-dev \
    # Useful utilities
    jq curl wget git unzip zip make \
    # Required for adding third-party apt repos and OAuth flows
    ca-certificates gnupg xdg-utils \
    # Large file storage for design assets (images, fonts, Figma exports)
    git-lfs \
    # GitHub CLI for PR/issue workflows
    gh \
    # Shell
    zsh \
    # Process/system inspection
    htop procps lsof strace \
    # File utilities
    tree file less \
    # Man pages
    man-db manpages \
    # Secret scanning
    gitleaks \
    # Terminal editors (fallback)
    vim-tiny nano \
    # Playwright Chromium runtime libraries.
    # Names use the t64 suffix introduced in Ubuntu 24.04's time_t64 transition;
    # see https://playwright.dev/docs/browsers#install-system-dependencies.
    libnss3 libnspr4 libatk-bridge2.0-0t64 libatk1.0-0t64 \
    libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 \
    libdrm2 libgbm1 libglib2.0-0t64 libpango-1.0-0 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libasound2t64 libxshmfence1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Switch to vscode user for tool installation
USER vscode

# Set zsh as default shell for vscode user
RUN sudo chsh -s $(which zsh) vscode


# Install mise (runtime version manager)
RUN curl https://mise.run | sh
ENV PATH="/home/vscode/.local/bin:${PATH}"

# Configure mise to auto-activate
RUN echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc && \
    echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc


# Install uv (fast Python package manager).
# uv 0.5.0+ installs to ~/.local/bin (already on PATH from the mise step).
RUN curl -LsSf https://astral.sh/uv/install.sh | sh


# Pre-install Python and Node via mise and make them the global default.
# `mise install` alone only downloads the runtime; `mise use --global`
# also writes ~/.config/mise/config.toml so they resolve outside a project.
RUN mise use --global python@3.13 node@22


# Install Claude Code using native installation (recommended method)
# The native install provides auto-updates and doesn't require Node.js
RUN curl -fsSL https://claude.ai/install.sh | bash


# Install global npm packages
RUN mise exec node -- npm install -g \
    typescript \
    tsx \
    prettier \
    eslint


# Install global Python tools via uv
RUN uv tool install ruff && \
    uv tool install black && \
    uv tool install mypy && \
    uv tool install pytest


# Install ZSH plugins and enable them in .zshrc.
# Cloning into ~/.oh-my-zsh/custom/plugins/ is necessary but not
# sufficient — Oh My Zsh only loads plugins listed in the
# plugins=(...) array, which the base image initialises to (git).
RUN git clone https://github.com/zsh-users/zsh-autosuggestions \
      ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions \
 && git clone https://github.com/zsh-users/zsh-syntax-highlighting \
      ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting \
 && sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions zsh-syntax-highlighting)/' ~/.zshrc
