package local.ateng.boot.system.service;

import com.mybatisflex.core.service.IService;
import local.ateng.boot.system.entity.SysPermission;

import java.util.List;

/**
 * 存储系统中的权限信息 服务层。
 *
 * @author 孔余
 * @since 1.0.0
 */
public interface SysPermissionService extends IService<SysPermission> {
    // 新增
    void addRole(SysPermission entity);

    // 查看列表
    List<SysPermission> listPermission();

    // 查看单个
    SysPermission getPermission(Integer id);
}
