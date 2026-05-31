# Droidian package repository

Put the generated `linux-*.deb` and `adaptation-samsung-r8q*.deb` packages in a
package repository before creating public rootfs images. The Droidian guide
supports GitHub Pages and GitLab Pages repositories.

The adaptation package has the repository line disabled at:

`sparse/usr/lib/adaptation-samsung-r8q/sources.list.d/community-samsung-r8q.list`

Replace the placeholder URL, install the matching `r8q.gpg` key at
`sparse/usr/share/keyrings/r8q.gpg`, then rebuild the adaptation package.
