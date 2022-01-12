# Image Zoom Plugin for Docusaurus 2

This plugin uses the [`medium-zoom`](https://github.com/francoischalifour/medium-zoom) library to allow for zoom in/out on images in your documentation.

![](/img/zoom_example.gif)

## Install and Configure

* npm install flexanalytics/plugin-image-zoom
* Add as a plugin to `docusaurus.config.js`, like this:
``` js
  plugins: [
    'plugin-image-zoom'
  ],
```
* Set the zoomSelector (optional, defaults to '.markdown img') in `docusaurus.config.js`, like this:
``` js
  themeConfig: {
    zoomSelector: '.markdown img',
  },
```

## Excluding Images from using Zoom

If you want to exclude certain images from using the zoom, then you'll need to apply a special tag to the image in your markdown and then use the `zoomSelector` option in `themeConfig` to exclude that tag.

For example, in your markdown you could wrap the image in an `<em>` tag, as such:
``` md
click on the *![](/img/portal/new.png)* button...
```

Then, exclude images inside an `<em>` tag, as such:
``` js
  themeConfig: {
    zoomSelector: '.markdown :not(em) > img',
  },
```


## See `plugin-image-zoom` in action

Check out the [FlexIt Analytics Docs](https://learn.flexitanalytics.com/) website, built 100% with Docusaurus, to see this plugin in action.
