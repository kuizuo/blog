export const siteInfo = {
  name: '愧怍',
  url: 'https://kuizuo.me',
  description: '道阻且长，行则将至。',
  copyrightStartYear: 2020,
  repository: 'https://github.com/kuizuo/blog',
  beian: {
    icp: '闽ICP备2020017848号-3',
    police: '闽公网安备35021102000847号',
  },
}

export function getPoliceRecordCode(): string {
  return siteInfo.beian.police.match(/\d+/)?.[0] ?? ''
}
