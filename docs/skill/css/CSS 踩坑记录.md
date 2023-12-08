

## 问题描述

使用left 和 top 去定位元素 发现没有生效
未生效的元素显示 
The `position: static` property prevents `left` from having an effect.
Try setting `position` to something other than `static`.

## 问题解决
忘记添加position属性了
```typescript
const Player: FC<{ position: Coordinate }> = ({ position }: { position: Coordinate }) => {  
    return (  
        <img  
            style={{ left: position.x, top: position.y, position: 'absolute' }}  
            src="src/assets/images/game/keeper.png"  
            alt=""  
        />  
    );  
};
```
