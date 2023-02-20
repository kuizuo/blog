module.exports = {
  extends: ['stylelint-config-standard-scss', 'stylelint-config-prettier-scss'],
  rules: {
    'selector-pseudo-class-no-unknown': [
      true,
      {
        // :global is a CSS modules feature to escape from class name hashing
        ignorePseudoClasses: ['global'],
      },
    ],
    'selector-class-pattern': null,
    'custom-property-empty-line-before': null,
    'selector-id-pattern': null,
    'declaration-empty-line-before': null,
    'no-descending-specificity': null,
    'comment-empty-line-before': null,
    'value-keyword-case': ['lower', { camelCaseSvgKeywords: true }],
  },
}
