import { createRouter, createWebHistory } from 'vue-router'

import Overview from '@/views/Overview.vue'
import UnitShareCastView from '@/views/UnitShareCastView.vue'
import UnitShareView from '@/views/UnitShareView.vue'
import WorkbenchView from '@/views/WorkbenchView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'overview', component: Overview },
    // 系数共享不再是通用表格页：授权页与转型核对页各自承载业务差异
    { path: '/unit_share', name: 'unit-share', component: UnitShareView },
    { path: '/unit_share/cast', name: 'unit-share-cast', component: UnitShareCastView },
    { path: '/:moduleKey', name: 'module', component: WorkbenchView, props: true },
  ],
})

export default router
